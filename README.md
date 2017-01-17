# Golang Rental API Example
This is an example of an API built with Golang. It uses routing, JWT, Google OAuth, &amp; MySQL. Operates on port 8080.


# Routes
"/" the index of the API, this prompts the user to log in using Google

"/rentals" only accessible to logged in users - this displays all the rentals that user has created. A POST request allows the user to create a new rental.

"/rentals/{id}" only accessible to logged in users - this displays a rental via its ID in the MySQL database. A DELETE request allows the user to delete the rental with the specified ID. In a production API, these actions would be scoped to the user that created this rental.

"/login" begins the process of authorizing the user to access the API, this sends the user to a Google OAuth page to sign in with their account. Once signed in, the users account is created in the DB - or the user is logged in to their existing account. The user receives a JWT which allows them full access to the protected routes in the API.

"/logout" deletes the JWT given to the user.

"/authcallback" part of the login process, this is the page the Google OAuth page redirects to after the user signs in.

"/settoken" part of the login process - creates and sets the JWT when the user is logged in

# DB

This API uses MySQL as the database, if testing the API, you will need to create a new database 'rentals' with two tables - rentals and users. Users have the fields id(int), name(varchar), & email(varchar). Rentals have id(int), city(varchar), address(varchar), rent(int), beds(int), baths(int), sqft(int), & user_id(varchar).

Note that the user_id on the rentals table refers to the Google user id stored in the JWT and not to the user id of the users table of this API.


