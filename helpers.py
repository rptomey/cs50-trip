import os
import requests
import urllib.parse
import overpy
import sqlite3

from flask import redirect, render_template, request, session
from functools import wraps

# Set up Overpass API
overpass = overpy.Overpass()

def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code

def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

def owner_required(f):
    """
    Decorate routes to require owner permissions.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("trip_owner") is None or session["trip_owner"] == "false":
            return redirect("/trips")
        return f(*args, **kwargs)
    return decorated_function

def set_city(city):
    # Get coordinates from database
    con = sqlite3.connect("trip.db")
    cur = con.cursor()
    rows = cur.execute("SELECT * FROM cities WHERE city = ?", city)
    con.close()

    # Remember coordinates
    session["city"] = rows[0]["city"]
    session["south"] = rows[0]["south_lat"]
    session["west"] = rows[0]["west_long"]
    session["north"] = rows[0]["north_lat"]
    session["east"] = rows[0]["east_long"]


def search_name_type_key(place_name, place_type, type_key):
    south = session["south"]
    west = session["west"]
    north = session["north"]
    east = session["east"]

    result = overpass.query(f"""
        [out:json];
        (nwr[{place_type}={type_key}]({south}, {west}, {north}, {east});)->.set;
        nwr.set["name"~"{place_name}"];
        out center;
        """)
    
    return result