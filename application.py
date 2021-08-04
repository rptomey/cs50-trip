import os
import re
import sqlite3

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required, owner_required, apology, set_city, search_name_type_key
# TODO: Figure out if I need the unused helper functions and/or if I'm missing something important.

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Make sure openroute service API key is set
if not os.environ.get("ORS_API_KEY"):
    raise RuntimeError("ORS_API_KEY not set")

@app.route("/")
@login_required
def index():
    """Show current trip plans or send to instructions if no trips are in process"""
    user_id = session["user_id"]

    # TODO: Make sure I'm not overwriting the trip ID when they return to the homepage if one is already set
    # Get latest trip id
    con = sqlite3.connect("trip.db")
    cur = con.cursor()
    trip = cur.execute("SELECT * FROM trips WHERE user_id = ? ORDER BY trip_id DESC LIMIT 1", user_id)

    # Handle no trips
    if len(trip) == 0:
        con.close()
        return redirect("/instructions")

    # Set trip id based on last trip in table
    trip_id = trip[0]["trip_id"]
    session["trip_id"] = trip_id

    # Check permissions to see if they are the owner
    permissions = cur.execute("SELECT * FROM permissions WHERE trip_id = ? AND user_id = ?", trip_id, user_id)
    con.close()

    # Display content if they are the trip owner
    # TODO: Decide if this is worth the effort and what should be different.
    # TODO: If I do decide to remove this, I have to remember to set trip owner in the session.
    if permissions[0]["user_permission"] == "owner":
        session["trip_owner"] =  "true"
        return render_template("index.html", trip=trip)

    # Otherwise display information about the trip
    return render_template("index.html", trip=trip)

@app.route("/instructions")
@login_required
def instructions():
    return render_template("instructions.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)
        
        # Ensure password was submitted
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        con = sqlite3.connect("trip.db")
        cur = con.cursor()
        rows = cur.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        con.close()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)
        
        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        # Get the values from the form submit
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Handle missing fields
        if not username or not password or not confirmation:
            return apology("must include username, password, and confirmation", 400)
        
        # Handle unsecure password
        if len(password) < 8 or re.search("[A-Z]", password) is None or re.search("[0-9]", password) is None or re.search("[!@#\$%\^&\*-_]", password) is None:
            return apology("review password requirements", 400)

        # Handle mismatched password and confirmation
        if password != confirmation:
            return apology("password must match confirmation", 400)

        # Open the database and either handle already registered users or add them to the table
        con = sqlite3.connect("trip.db")
        cur = con.cursor()
        rows = cur.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 0:
            con.close()
            return apology("user already exists", 400)

        hashed_password = generate_password_hash(password)
        cur.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashed_password)
        con.close()

@app.route("/create-trip", methods=["GET", "POST"])
@login_required
def create_trip():
    """Create a new trip"""
    user_id = session["user_id"]

    if request.method == "POST":
        # Get the values from the form submit
        trip_city = request.form.get("trip_city")
        trip_start_date = request.form.get("trip_start_date")
        trip_end_date = request.form.get("trip_end_date")
        trip_must_sees = request.form.get("trip_must_sees")

        # Handle empty fields
        if not trip_city or not trip_start_date or not trip_end_date:
            return apology("missing trip details", 400)

        con = sqlite3.connect("trip.db")
        cur = con.cursor()
        city_id = cur.execute("SELECT city_id FROM cities WHERE city = ?", trip_city)[0]["city_id"]
        cur.execute("INSERT INTO trips (trip_start_date, trip_end_date, city_id, must_sees) VALUES (?, ?, ?, ?)", trip_start_date, trip_end_date, city_id, trip_must_sees)
        trip_id = cur.execute("SELECT trip_id FROM trips WHERE user_id = ? ORDER BY trip_id DESC LIMIT 1")[0]["trip_id"]
        cur.execute("INSERT INTO permissions (trip_id, user_id, user_permission) VALUES (?, ?, ?)", trip_id, user_id, "owner")
        con.close()
        session["trip_id"] = trip_id

        return redirect("/")

    if request.method == "GET":
        return render_template("create-trip.html")

@app.route("/select-trip", methods=["POST"])
@login_required
def select_trip():
    """Switch between trips"""
    # Get the values from the form submit
    trip_id = request.form.get("trip_id")

    # Change the trip id in session
    session["trip_id"] = trip_id

    # Check if user is the trip owner
    user_id = session["user_id"]
    con = sqlite3.connect("trip.db")
    cur = con.cursor()
    rows = cur.execute("SELECT * FROM permissions WHERE trip_id = ? AND user_id = ?", trip_id, user_id)
    con.close()

    if rows[0]["user_permission"] == "owner":
        session["trip_owner"] = "true"
    else:
        session["trip_owner"] = "false"

    # Send user to trips page
    return redirect("/trips")

@app.route("/trips")
@login_required
def trips():
    # Handle no trip id in session
    if not session["trip_id"]:
        return redirect("/create-trip")

    # Get trip id and user id from session
    trip_id = session["trip_id"]
    user_id = session["user_id"]

    # Get data for current trip
    con = sqlite3.connect("trip.db")
    cur = con.cursor()
    current_trip = cur.execute("SELECT * FROM trips WHERE trip_id = ?", trip_id)

    # Get data for all other trips
    other_trips = cur.execute("SELECT * FROM trips WHERE user_id = ? AND trip_id != ?", user_id, trip_id)
    con.close()

    # Render trips page
    return render_template("trips.html", current=current_trip, others=other_trips)

@app.route("/add-party", methods=["GET", "POST"])
@login_required
@owner_required
def add_party():
    """Add existing users to your trip"""

    if request.method == "POST":
        # Get the values from the form submit
        user_name = request.form.get("user_name")
        user_permission = request.form.get("user_permission")

        # Handle missing values
        if not user_name or not user_permission:
            return apology("must include username and permission level", 400)

        # Get trip id from session
        trip_id = session["trip_id"]

        # Handle nonexistent user
        con = sqlite3.connect("trip.db")
        cur = con.cursor()
        rows = cur.execute("SELECT * FROM users WHERE username = ?", user_name)
        
        if len(rows) != 1:
            con.close()
            return apology("user does not exist", 400)

        # Get user_id from rows result
        user_id = rows[0]["user_id"]

        # Handle user already in trip
        rows = cur.execute("SELECT * FROM permissions WHERE trip_id = ? AND user_id = ?", trip_id, user_id)

        if len(rows) > 0:
            con.close()
            return apology("user already invited to trip", 400)

        # Add user to permissions table
        cur.execute("INSERT INTO permissions (trip_id, user_id, user_permission) VALUES (?, ?, ?)", trip_id, user_id, user_permission)
        con.close()

        return redirect("/manage-party")
    
    if request.method == "GET":
        return render_template("add-party.html")

@app.route("/manage-party")
@login_required
@owner_required
def manage_party():
    """Display current party members and link to add/delete/update pages"""
    trip_id = session["trip_id"]

    # Get list of users currently in party for this trip
    con = sqlite3.connect("trip.db")
    cur = con.cursor()
    rows = cur.execute("SELECT u.username, p.user_permission FROM users u LEFT JOIN permissions p ON p.user_id = u.user_id WHERE p.trip_id = ?", trip_id)
    con.close()

    # Handle no users
    if len(rows) == 0:
        return redirect("/add-party")

    # Render page with the rows of users
    return render_template("manage-party.hmtl", party=rows)

@app.route("/remove-party", methods=["GET", "POST"])
@login_required
def remove_party():
    """Remove users from current trip"""
    trip_id = session["trip_id"]

    if request.method == "POST":
        # Get info from deletion form
        user_name = request.form.get("user_name")

        # Get user id from users table
        con = sqlite3.connect("trip.db")
        cur = con.cursor()
        rows = cur.execute("SELECT * FROM users WHERE username = ?", user_name)
        user_id = rows[0]["user_id"]

        # Delete user id from permissions table for just this trip
        cur.execute("DELETE FROM permissions WHERE trip_id = ? AND user_id = ?", trip_id, user_id)
        con.close()
        
        # Send back to manage party page
        return redirect("/manage-party")

    if request.method == "GET":
        # Get usernames for this trip
        con = sqlite3.connect("trip.db")
        cur = con.cursor()
        users = cur.execute("SELECT u.username FROM users u LEFT JOIN permissions p ON p.user_id = u.user_id WHERE p.trip_id = ? ORDER BY u.username ASC", trip_id)
        con.close()

        # Handle no users on trip
        if len(users) == 0:
            return redirect("/add-party")

        # Send to the form
        return render_template("remove-party.html", users=users)

@app.route("/update-permissions", methods=["GET", "POST"])
@login_required
@owner_required
def update_permissions():
    """Set new permission level for a user on the trip"""
    trip_id = session["trip_id"]

    if request.method == "POST":
        # Get info from update form
        user_name = request.form.get("user_name")
        user_permission = request.form.get("user_permission")

        # Get user id from users table
        con = sqlite3.connect("trip.db")
        cur = con.cursor()
        rows = cur.execute("SELECT * FROM users WHERE username = ?", user_name)
        user_id = rows[0]["user_id"]

        # Set new permission for the user for just this trip
        cur.execute("UPDATE permissions SET user_permission = ? WHERE trip_id = ? AND user_id = ?", user_permission, trip_id, user_id)
        con.close()
        
        # Send back to manage party page
        return redirect("/manage-party")
    
    if request.method == "GET":
        # Get usernames for this trip
        con = sqlite3.connect("trip.db")
        cur = con.cursor()
        users = cur.execute("SELECT u.username FROM users u LEFT JOIN permissions p ON p.user_id = u.user_id WHERE p.trip_id = ? ORDER BY u.username ASC", trip_id)
        con.close()

        # Handle no users on trip
        if len(users) == 0:
            return redirect("/add-party")

        # Send to the form
        return render_template("update-permissions.html", users=users)

@app.route("/places", methods=["GET", "POST"])
@login_required
def places():
    """Add sites and restaurants to interested list"""
    trip_id = session["trip_id"]
    user_id = session["user_id"]

    if request.method == "POST":
        # Get the values from the form submit
        place_id = request.form.get("place_id")
        place_name = request.form.get("place_name")
        place_category = request.form.get("place_category")
        place_lat = request.form.get("place_lat")
        place_long = request.form.get("place_long")
        place_interest = request.form.get("place_interest")
        
        # Handle value for must sees
        if request.form.get("place_must_see"):
            place_must_see = 1
        else:
            place_must_see = 0

        # Handle empty fields
        if not place_id or not place_name or not place_category or not place_lat or not place_long or not place_interest:
            return apology("missing place details", 400)

        # Add location to places table
        con = sqlite3.connect("trip.db")
        cur = con.cursor()
        cur.execute("INSERT INTO places (trip_id, user_id, place_id, place_name, place_category, place_lat, place_long, place_interest, must_see) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", trip_id, user_id, place_id, place_name, place_category, place_lat, place_long, place_interest, place_must_see)
        con.close()
        return redirect("/places")

    if request.method == "GET":
        con = sqlite3.connect("trip.db")
        cur = con.cursor()
        rows = cur.execute("SELECT * FROM places WHERE trip_id = ? AND user_id = ? ORDER BY place_name ASC", trip_id, user_id)
        con.close()
        return render_template("places.html", places=rows)

@app.route("/trip-plans")
@login_required
def trip_plans():
    trip_id = session["trip_id"]

    # Get trip plans from the database
    con = sqlite3.connect("trip.db")
    cur = con.cursor()
    rows = cur.execute("SELECT * FROM plans WHERE trip_id = ?", trip_id)
    con.close()

    # Render page with trip plans
    return render_template("trip-plans.html", plans=rows)

@app.route("/set-plans", methods=["GET", "POST"])
@login_required
@owner_required
def set_plans():
    if request.method == "POST":
        trip_id = session["trip_id"]

        # TODO: Figure out how to get data from the page and set it to the places array of JSON objects here
        places = []

        if len(places) == 0:
            return apology("no places set", 400)

        # Start index at 1
        index = 1

        # Open the database then start writing to plans table
        con = sqlite3.connect("trip.db")
        cur = con.cursor()

        for place in places:
            date = place["date"]
            activity_type = place["activity_type"]

            if activity_type != "travel":
                activity_index = index
                index += 1
                activity_name = place["activity_name"]
                activity_start_time = place["activity_start_time"]
                activity_end_time = place["activity_end_time"]
                activity_lat = place["activity_lat"]
                activity_long = place["activity_long"]
                cur.execute("INSERT INTO plans (trip_id, date, activity_index, activity_name, activity_type, activity_start_time, activity_end_time, activity_lat, activity_long) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", trip_id, date, activity_index, activity_name, activity_type, activity_start_time, activity_end_time, activity_lat, activity_long)
            elif activity_type == "travel":
                activity_name = place["activity_name"]
                activity_start_time = place["activity_start_time"]
                activity_end_time = place["activity_end_time"]
                cur.execute("INSERT INTO plans (trip_id, date, activity_name, activity_type, activity_start_time, activity_end_time) VALUES(?, ?, ?, ?, ?, ?)", trip_id, date, activity_name, activity_type, activity_start_time, activity_end_time)
        
        con.close()
        return redirect("/trip-plans")

    if request.method == "GET":
        trip_id = session["trip_id"]

        # Get trip details
        con = sqlite3.connect("trip.db")
        cur = con.cursor()
        trip = cur.execute("SELECT * FROM trips WHERE trip_id = ?", trip_id)

        # TODO: Fix this select so that it's only giving me one row per place, with an average score and total votes
        # TODO: Break this into two selects so that we can separate the must haves out
        # Get all potential places for this trip
        places = cur.execute("SELECT * FROM places WHERE trip_id = ?", trip_id)
        con.close()

        # Handle no places
        if len(places) == 0:
            return apology("no places have been added to this trip", 400)

        # Render the page with trip details and places available
        return render_template("set-plans.html", trip=trip, places=places)


# Config errorhandler function
def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)

# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

# TODO: figure out how place categories are going to be implemented
# TODO: all of the user interface stuff...