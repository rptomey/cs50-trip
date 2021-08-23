# Ptrips
#### Video Demo:  <URL HERE>
#### Description:
Your README.md file should be minimally multiple paragraphs in length, and should explain what your project is, what each of the files you wrote for the project contains and does, and if you debated certain design choices, explaining why you made them. Ensure you allocate sufficient time and energy to writing a README.md that you are proud of and that documents your project thoroughly. Be proud of it!

The Ptrips web app came to me as an idea to create a place to collaboratively plan trips with other people. When going sightseeing or out to restaurants, it can be hard to make sure that everyone's wishes are being met. While I wasn't able to finish building Ptrips during the time I allotted for my final project, I plan to eventually follow through on the rest of the features because I think it will make for a good portfolio piece. That said, I'll walk through what I was and wasn't able to complete - as well as some of the noteworthy parts of the design and development process.

Ptrips' scope encompassed a lot of functionality, ranging from group management and permissions to creating an itinerary. I was able to complete the following components:
* A database with tables for site users, city information, trip information, trip-specific user permissions, trip-specific points of interest, and finalized itineraries.
* A back end written in Python, leveraging flask, for serving up the site, accepting form information, querying APIS, and communicating with the database.
* The ability to create a new trip.
* The ability to search for points of interest by name or by category.
* The ability to explore points of interest on a map, then add them to the places the user wants to see.

That all ended up being way more work than I expected, so I had to call it. The most critical piece of functionality that I wasn't able to get to was the ability for the trip organizer to see where members of the party wanted to go, add points of interest to an itinerary, and then finalize it for all of the party to view.

When I came up with the idea for this project, I thought I would just use the Google Maps API. Once I started digging in, I was disappointed to see that the Google Maps API wasn't as friendly to personal projects as I would have hoped. Apparently, they raised the price of usage in 2018. The API functionality that I would have used required a credit card on file, and while a certain amount of requests were free, I didn't want to risk a bot stumbling on my site, submitting a ton of requests, and running up a significant bill.

Because of this roadblock, I had to find a free alternative. I ended up leveraging OpenStreetMaps. While I really appreciate that there was a free option available, its user-submitted nature meant that the quality and contents of each tagged place could vary widely. The tagged attributes weren't very easy to use either. For example, if I wanted to search for museums, my search string would have to be "tourism"="museum", but if I wanted to look for stadiums, I would instead look for "leisure=stadium".

Beyond the difficulty in using the Overpass API, which connects to that data source, I had to pull in other free things to replicate Google Maps functionality. In order to put a map on a page, I had to sign up for a MapBox account, get an API key for a tile set, then pull in Leaflet (a JavaScript framework) to be able to build maps.

My next challenge would have been figuring out how to help users schedule while allowing for enough time to travel between points of interest. As I said, I eventually want to do this, but if I do, I might reconsider and refactor the code to use Google Maps and make sure that my site just isn't publicly accessible in order to keep it from being abused.

All of that said, even though I didn't finish everything I set out to do, I'm proud of what I accomplished so far. I learned a ton, and I managed to take off some of the training wheels that were offered by the cs50 IDE.