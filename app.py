import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():

    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

    stocks = db.execute("SELECT symbol, SUM(shares) AS total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares > 0)", session["user_id"])

    total_holding = cash

    for stock in stocks:
        quote = lookup(stock["symbol"])
        stock["name"] = quote["name"]
        stock["price"] = quote["price"]
        stock["holding"] = stock["price"] * stock["total_shares"]
        total_holding += stock["holding"]

    return render_template("index.html", stocks=stocks, cash=cash, total_holding=total_holding)

    """Show portfolio of stocks"""


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        stock = request.form.get("symbol")
        symbol = lookup(request.form.get("symbol"))
        shares = request.form.get("shares")

        # if unable to buy stocks
        
        if not shares.isdigit():
            return apology("enter number of stocks")
        if not stock or symbol == None:
            return apology("enter stock name")
        elif int(shares) < 0:
            return apology("enter number of stocks")

        price = symbol["price"]

        total_cost = int(shares) * price

        funds = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]

        if funds < total_cost:
            return apology("insufficient funds")

        # recording transactions

        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", session["user_id"], symbol["symbol"], shares, price)

        # updating cash

        balance = funds - (float(shares) * price)

        db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, session["user_id"])

        return redirect("/")

    else:
        return render_template("buy.html")
    """Buy shares of stock"""


@app.route("/history")
@login_required
def history():
    transactions = db.execute("SELECT symbol, shares, price, timestamp FROM transactions WHERE user_id = ?", session["user_id"])

    # checking if stock was bought or sold

    for transaction in transactions:
        shares = transaction["shares"]
        if shares < 0:
            shares = -1 * shares
            transaction["shares"] = shares
            transaction["status"] = "sold"
        else:
            transaction["status"] = "bought"

    return render_template("history.html", transactions=transactions)
    """Show history of transactions"""


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
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("enter stock symbol")
        symbol = lookup(request.form.get("symbol"))
        if symbol == None:
            return apology("invalid Stock Symbol")
        return render_template("quoted.html", symbol=symbol)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("must provide confirmation", 400)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 0:
            return apology("username already taken", 400)

        password = generate_password_hash(request.form.get("password"))

        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), password)

        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/quote")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = lookup(request.form.get("symbol"))
        check_shares_db = db.execute("SELECT SUM(shares) AS total_shares FROM transactions WHERE user_id = ? AND symbol = ? GROUP BY symbol HAVING SUM(shares > 0)", session["user_id"], symbol["symbol"])
        check_shares = check_shares_db[0]["total_shares"]
        shares = request.form.get("shares")
        if int(shares) > check_shares:
            return apology("insufficient shares owned", 400)
        price = symbol["price"]
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        updated_cash = cash + (int(shares) * price)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", updated_cash, session["user_id"])
        shares = -1 * int(shares)
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", session["user_id"], symbol["symbol"], shares, price)
        return redirect("/")
    else:
        stocks = db.execute("SELECT symbol FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares > 0)", session["user_id"])
        return render_template("sell.html", stocks=stocks)
    """Sell shares of stock"""

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        if not request.form.get("previous") or not request.form.get("new") or not request.form.get("confirmation"):
            return apology("enter password details")
        check_previous = db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"]
        previous = request.form.get("previous")
        if check_password_hash(check_previous, previous) == "False":
            return apology("incorrect password entered")
        elif request.form.get("new") != request.form.get("confirmation"):
            return apology("re-enter password correctly")
        password = generate_password_hash(request.form.get("new"))
        db.execute("UPDATE users SET hash = ? WHERE id = ?", password, session["user_id"])
        return redirect("/")
    else:
        return render_template("change_password.html")
