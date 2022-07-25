# Authbackend

### Approach

* Part 1 - Server
  * First, we will create an express server and hook it up to our mongo database.
  * Second, we will install the encryption node module bcrypt.
    * bcrypt gives us access to password generation and authentication functionality for logging users in to our application.
  * Third, we will implement the user creation route using the bcrypt salt/hash functions to take our new users password and encrypt it before saving it to the database.
  * Fourth, we will implement the user login route to authenticate our user with the bcrypt compare function.
  * Fifth, we will create a put route for editing user permissions (this is the sort of thing that would only be reserved for admins) so that we may grant administrator status to our users.
  * Sixth, we will create a simple route that returns a JSON success object, but only after the user has authenticated and is authorized to view the resource.

### Requirements (Back-End - Boilerplate)

* Create a new github repo called authbackend, clone the repo to your computer and add the link to populi. Note: when you create this repository, you must add a README, and a node .gitignore template. ✅

* Initialize the repo with express-generator.
  * npx express-generator . ✅
* Create a new file ./.env and add the following environment variable to it
  * PORT=4000. ✅
  * Note: This will change the server port to 4000 on startup
* [Optional] Install nodemon on the server and add the custom dev command in the package.json
  * npm i nodemon
  * "scripts": {
    "start": "node ./bin/www",
    "dev": "nodemon ./bin/www"
  } ✅
* Install the CORS package by running "npm i cors" in ./
  * npm i cors. ✅
* Add the following code, after the line var app = express();, to app.js:
  * //enable cors
  const cors = require("cors");
  app.use(cors());
  app.options("*", cors()); ✅
* Install mongodb and dotenv
  * npm i mongodb dotenv ✅
* Add your Mongo Atlas connection string to the ./.env file
  * MONGO_URI=mongodb+srv://<myusername>:<mypassword>@<mycluster>.mongodb.net/?retryWrites=true&w=majority
    * Note: You will need to replace <myusername>, <mypassword>, and <mycluster> with the values for your URI string.
  * Add the default blog name to the .env file
    * MONGO_DATABASE=blog ✅
* Create a new file ./mongo.js and add the following code to it:
  * const { MongoClient } = require("mongodb");
    require("dotenv").config(); ✅

    let db;

    async function mongoConnect() {
      const uri = process.env.MONGO_URI;
      const client = new MongoClient(uri);
      try {
        await client.connect();
        db = await client.db(process.env.MONGO_DATABASE);
        console.log("db connected");
      } catch (error) {
        console.error(error)
      }
    }
    function blogsDB() {
      return db;
    }
    module.exports = {
      mongoConnect,
      blogsDB,
    };
* Add the following code, after the line var app = express();, to app.js:
  * var { mongoConnect } = require('./mongo.js');
    mongoConnect(); ✅

### Requirements (Back-End - User-Creation)

* Second, we will install the encryption node module bcrypt.
  * bcrypt gives us access to password generation and authentication functionality for logging users in to our application.
* Third, we will implement the user creation route using the bcrypt salt/hash functions to take our new users password and encrypt it before saving it to the database.

* In the root ./, install bcryptjs and uuidv4
  * npm i bcryptjs uuidv4 ✅
  * Note: 
    * Here are the bcrypt docs: https://www.npmjs.com/package/bcryptjs
    * Here are the uuidv4 docs: https://github.com/thenativeweb/uuidv4#readme
* In app.js add the following code: ✅
  * var authRouter = require('./routes/auth');
  * app.use('/auth', authRouter);
* Create a new file ./routes/auth.js and implement the following in it: ✅
  * Add these lines of code to the top of the file: ✅
    * var express = require("express");
      var router = express.Router();
      const bcrypt = require('bcryptjs');
      const { uuid } = require('uuidv4');
      const { blogsDB } = require("../mongo");
  * Add this line to the bottom of the file: ✅
    * module.exports = router
  * Write a new async(!) function in the global scope called createUser. Implement the following in createUser:
    * Add two params to the function definition: username and passwordHash
      * const createUser = async (username, passwordHash) => {}. ✅
    * Add this line of code to connect to the users collection:
      * const collection = await blogsDB().collection("users") ✅
      * Note: You do not have to create the users collection in mongodb before saving to it. Mongo will automatically create the users collection upon insert of a new document. ✅
    * Implement mongodb functionality to insert() the user into the collection:
      * const user = {
          username: username, 
          password: passwordHash,
          uid: uuid() // uid stands for User ID. This will be a unique string that we will can to identify our user
        }
    * Add a try catch block within your code to return true if the save was successful and false if it was not:
      * try {
        // Save user functionality
        return true;
      } catch (e) {
        console.error(e);
        return false;
      }
  * Create a new async(!) POST route "/auth/register-user" and implement the following: ✅
    The user's username and password will come from the req.body in this request. ✅
      * const username = req.body.username
      * const password = req.body.password
    * Add these lines to generate a salted hash of your users password and save the new user to the database. ✅
      * const saltRounds = 5; // In a real application, this number would be somewhere between 5 and 10. ✅
        let userSaveSuccess = false; 
        const salt = await bcrypt.genSalt(saltRounds)
        const hash = await bcrypt.hash(password, salt)
        const userSaveSuccess = await createUser(username, hash);
    * Respond at the end of the route with a json success object
      * res.json({success: userSaveSuccess}). ✅

  * Create a new async POST route "/auth/login-user" and implement the following:
    * Add mongodb code to fetch a user from the database where the username matches the incoming username from req.body
      * const user = await collection.findOne({
          username: req.body.username
        }) ✅
    * Add the following code to check the users stored password with the req.body password:
      * const match = await bcrypt.compare(req.body.password, user.password);
    * Implement functionality at the end of the route to respond a json object. If the passwords match, then the object should have "success": true; if the passwords do not match, the object should have "success": false. ✅

//=======================================================================================

### Approach - Part 2: Persistent Login

* First, we will add persist login functionality with JSON Web Tokens
* Second, we will create a new react app for our front-end
* Third, we will create some basic pages including the registration and login page
* Fourth, we will implement the auth flow functionality

### Requirements (Back-End - JWT Implementation)

* First, we will add persist login functionality with JSON Web Tokens

* In the server, implement the following:
  * In the root ./, install jsonwebtoken
    * npm i jsonwebtoken ✅
  * in ./.env, add the following environment variables:
    * JWT_SECRET_KEY = CodeImmersives2022 ✅
    * TOKEN_HEADER_KEY = ci_token_header_key ✅
  * In ./routes/auth.js, implement the following:
    * Add these three lines of code to the top of the file:
      * const dotenv = require('dotenv');
        const jwt = require('jsonwebtoken');
        dotenv.config(); ✅
    * In the "/auth/login-user" route, implement the following:
      * Add these lines of code AFTER you fetch the user from the database and authenticate their username/password credentials using bcrypt:
        * const jwtSecretKey = process.env.JWT_SECRET_KEY;
          const data = {
              time: new Date(),
              userId: user.uid // Note: Double check this line of code to be sure that user.uid is coming from your fetched mongo user 
          }
          const token = jwt.sign(data, jwtSecretKey);
      * At the end of the route, update the res.json method to send the token with the response along with the success message
        * res.json({success: true, token}) ✅
    * Add a new GET route "/auth/validate-token" and implement the following:
      * Add these lines of code to the route:
        * const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
          const jwtSecretKey = process.env.JWT_SECRET_KEY;
  
          try {
            const token = req.header(tokenHeaderKey);
      
            const verified = jwt.verify(token, jwtSecretKey);
            if(verified){
                return res.json({success: true});
            }else{
                // Access Denied
                throw Error("Access Denied")
            }
          } catch (error) {
            // Access Denied
            return res.status(401).json({success: true, message: String(error)});
          } ✅

### Requirements (Front-End-Boilerplate)

* Second, we will create a new react app for our front-end

* Create a new github repo called authfrontend, clone the repo to your computer and add the link to populi.
* Initialize the repo with create-react-app.
    * npx create-react-app .
* Install react-router
    * npm i react-router-dom@6 ✅
* Configure react-router by adding <BrowserRouter> to index.js.
  * import { BrowserRouter } from "react-router-dom";
  * root.render(
      <React.StrictMode>
        <BrowserRouter>
        <App />
        </BrowserRouter>
      </React.StrictMode>
    );

### Requirements (Front-End - Authentication) ✅

* Third, we will create some basic pages including the registration and login page

* Create a new folder ./src/Pages
* Create a new file ./src/Pages/RegistrationPage.js with a default exported react component <RegistrationPage />. ✅
* Create a new file ./src/Pages/LoginPage.js with a default exported react component <LoginPage />. ✅
* Create a new file ./src/Pages/HomePage.js with a default exported react component <HomePage />. ✅
* Create a new folder ./src/Components
* Create a new file ./src/Components/NavBar.js with a default exported react component <NavBar /> and implement the following:
  * Add this import statement:
    * import { Outlet, Link } from "react-router-dom";
  * Add the following code to the JSX return statement of <NavBar />:
    * <div>
        <nav>
          <h3>NavBar</h3>
          <ul>
            <li>
              <Link to="/">Home</Link>
            </li>
            <li>
              <Link to="/login">Login</Link>
            </li>
            <li>
              <Link to="/registration">Registration</Link>
            </li>
          </ul>
        </nav>
        <Outlet />
      </div>
* In <App>, implement the following:
  * Note: You will have to write the import statements for importing Pages and Components in order to support the following code.
  * Add this import statement:
    * import { Routes, Route } from "react-router-dom";
  * Add the routes elements to the JSX 
    * <Routes></Routes> ✅
  * Create a new route where the path is "/" and the element is <Navbar />, then nest the following routes within it: ✅
    * A new index route with the element <HomePage /> ✅
    * A new route with the path "/login" and the element <LoginPage /> ✅
    * A new route with the path "/registration" and the element <RegistrationPage />
    * The routes should look similar to this:
    * <Routes>
        <Route path="/" element={<Navbar />}>
          <Route index element={<HomePage />} />
          <Route path="login" element={<LoginPage />} />
          <Route path="registration" element={<RegistrationPage />} />
        </Route>
      </Routes> ✅

### Requirements (Front-End - JWT Implementation)

* Fourth, we will implement the auth flow functionality. ✅

* In the root folder ./, implement the following:
  * Add a new env file ./.env.local and add the following environment variables to it:
    * REACT_APP_TOKEN_HEADER_KEY = ci_token_header_key
    * REACT_APP_URL_ENDPOINT = http://localhost:4000
    * Note: For react applications, environment variables MUST start with REACT_APP and by convention the file is named .env.local. ✅
* Add a new file ./src/Auth.js and implement the following:
  * Add a new variable in the global scope:
    * const urlEndpoint = process.env.REACT_APP_URL_ENDPOINT; ✅
  * Add a new exported function registerUser that does the following:
    * It should have two function parameters: username and password
      * export const registerUser = (username, password) => {}
    * In the function body, it should create a POST request to `${urlEndpoint}/auth/register-user` with a JSON.stringified object containing the user's username and password:
      * body: JSON.stringify({
        username,
        password
      })
      * Note: Do not forget to set the following header in the POST request:
        * headers: {
            'Content-Type': 'application/json'
          }
    * Finally, it should return true or false based upon the success message returned from the server. ✅
  * Add a new exported function loginUser that does the following:
    * It should have two function parameters: username and password
    * In the function body, it should create a POST request to `${urlEndpoint}/auth/login-user` with a JSON.stringified object containing the user's username and password:
      * body: JSON.stringify({
        username,
        password
      })
      * headers: {
          'Content-Type': 'application/json'
        } ✅
    * It should await to receive a success message from the server. ✅
    * If the login was successful, it should set a new token in local storage:
      * const responseJSON = await response.json();
        if (responseJSON.success) {
          localStorage.setItem(process.env.REACT_APP_TOKEN_HEADER_KEY, JSON.stringify(responseJSON.token));
        }
      * Note: We will be using this local storage item on the front end to determine if the user is logged in or not. If the token exists, we assume the user is logged in. If the token does not exist for any page that requires authentication, we will redirect the user to the login page. ✅
    * It should return true if all the above executed properly. ✅
  * Add a new exported function logoutUser that does the following:
    * localStorage.removeItem(process.env.REACT_APP_TOKEN_HEADER_KEY);
  * Add a new exported function getUserToken that does the following:
    * return JSON.parse(localStorage.getItem(process.env.REACT_APP_TOKEN_HEADER_KEY)); ✅

* In <App />, implement the following:
  * Add a new state variable isAuthLoading. ✅
  * Pass the isAuthLoading state variable as well as its setter function as props into <NavBar>, <RegistrationPage />, and <LoginPage />. ✅

* In <RegistrationPage />, implement the following:
  * Add two new state variables: username and password. ✅
  * Add two new text input fields and hook them up to username and password (the input fields should set the values for the two state variables). ✅
  
  * Import the following functions from ./src/Auth.js: registerUser and loginUser. ✅
  * Add a button called Signup with the following functionality in the async onClick handler: ✅
    * The function should call registerUser and pass in the username and password as arguments: ✅
      * registerUser(username, password)
    * It should call props.setIsAuthLoading(true) ✅
    * It should await for registerUser to return true ✅
    * If registerUser returned true, it should call loginUser with the username and password as arguments ✅
    * If loginUser returned true, it should:
      * Call props.setIsAuthLoading(false) ✅
      * Programmatically redirect to "/"
        * const navigate = useNavigate()
        * navigate(`/`) ✅

* In <LoginPage />, implement the following: 
  * Add two new state variables: username and password. ✅
  * Add two new text input fields and hook them up to username and password. ✅
  * Import the function loginUser from ./src/Auth.js. ✅
  * Add a button called Login with the following functionality in the async onClick handler: ✅
    * The function should call loginUser and pass in the username and password as arguments: ✅
      * loginUser(username, password) ✅
    * It should call props.setIsAuthLoading(true) ✅
    * It should await for loginUser to return true ✅
    * If loginUser returned true, it should:
      * Call props.setIsAuthLoading(false)
      * Programmatically redirect to "/"
        * const navigate = useNavigate()
        * navigate(`/`) ✅
  
* In <NavBar />, implement the following:
  * Import the following functions from ./src/Auth.js: getUserToken and logoutUser
  * Add a new state variable called userToken. ✅
  * Add a new useEffect to <NavBar />
    * useEffect(()=>{
      const userToken = getUserToken()
      setUserToken(userToken)
    }, [isAuthLoading])
  * Update the return JSX in <NavBar /> to be the following:
    * <div>
        <nav>
          <h3>NavBar</h3>
          <ul>
            <li>
              <Link to="/">Home</Link>
            </li>
            {!userToken && 
              <li>
                <Link to="/login">Login</Link>
              </li>
              <li>
                <Link to="/registration">Registration</Link>
              </li>
            }
          </ul>
          {userToken && 
            <span><strong>You Are Logged In</strong></span>
            <button onClick={()=>{
              logoutUser()
            }}>Logout</button>
          }
        </nav>
        <Outlet />
      </div> ✅

* Note: If all the above was implemented correctly, you should be able to do the entire auth flow from the front end. Register a user, login as that user and logout from that user. You should also see the NavBar update dynamically based upon your login status. ✅

//========================================================================

### Approach - Part 3: Authorization and Access Tokens

* First, we will improve our auth flow by adding a scope flag to our token to inform the server if our user is an admin or a user. 
* Second, we will update our token validation route to check for the user scope and return a message based upon that scope. Simulating an admin gaining access to a privileged resource.
* Third, we will implement the client side code to request a protected resource from the server with the JWT access token.

### Requirements (Back-End - Access Token)

* In the server, implement the following:
  * In "/auth/login-user", update the variable data to be the following:
    * const data = {
        time: new Date(),
        userId: user.uid, // Note: Double check this line of code to be sure that user.uid is coming from your fetched mongo user
        scope: username.includes("codeimmersives.com") ? "admin" : "user"
      };
  * In "/auth/validate-token", update the code to be the following:
    * router.get("/validate-token", (req, res) => {
        const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
        const jwtSecretKey = process.env.JWT_SECRET_KEY;

        try {
          const token = req.header(tokenHeaderKey);
          const verified = jwt.verify(token, jwtSecretKey);

          if (verified && verified.scope === "admin") {
            return res.json({ success: true, message: "Speak 'Friend' and enter..." });
          }
          if (verified && verified.scope === "user") {
            return res.json({ success: true, message: "You shall not pass!" });
          }

          throw Error("Access Denied");
        } catch (error) {
          // Access Denied
          return res.status(401).json({ success: true, message: String(error) });
        }
      });
  
### Requirements (Front-End - Secret Message)

* In <HomePage />, implement the following:
  * Add a new state variable called secretMessage
  * Import getUserToken from ./src/Auth.js
  * Add a new function called requestSecretMessage in the <HomePage /> body:
    * const requestSecretMessage = async () => {
        const url = `${process.env.REACT_APP_URL_ENDPOINT}/auth/validate-token`;
        const response = await fetch(url, {
          method: "GET",
          headers: {
            "Content-Type": "application/json",
            [process.env.REACT_APP_TOKEN_HEADER_KEY]: getUserToken(),
          },
        });
        const responseJSON = await response.json();
        setSecretMessage(responseJSON.message)
        return responseJSON;
      };
    * Note: We are sending the users token back in the headers of the request. This is another layer of added security for our application. 
  * Add a new button called Get Message and add an onClick handler that calls the requestSecretMessage function
* If everything was set up properly, you should be able to register a new user with an email ending in @codeimmersives.com and see the secret message appear on the Home Page.