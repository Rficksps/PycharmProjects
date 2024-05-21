import datetime
import sqlite3
import time
import pandas as pd
from datetime import timezone
from flask import Flask, render_template, request, redirect, url_for, session, flash
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = 's3cr3t'

def init_db():
    with app.app_context():
        db = sqlite3.connect('events3.db')
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT, wins INTEGER DEFAULT 0)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, start_date UNIX TIME, end_date UNIX TIME, description TEXT, creator_id INTEGER)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS event_invitations (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, sender_id INTEGER, receiver_id INTEGER, status TEXT, FOREIGN KEY (event_id) REFERENCES events(id), FOREIGN KEY (sender_id) REFERENCES users(id), FOREIGN KEY (receiver_id) REFERENCES users(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_events (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, event_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (event_id) REFERENCES events(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_tournaments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, tournament_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (tournament_id) REFERENCES tournaments(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS friend_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER, status TEXT, FOREIGN KEY (sender_id) REFERENCES users(id), FOREIGN KEY (receiver_id) REFERENCES users(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_favorites (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, game_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (game_id) REFERENCES game(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS tournaments (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, start_date UNIX TIME, end_date UNIX TIME, description TEXT, creator_id INTEGER, game_id INTEGER, FOREIGN KEY (game_id) REFERENCES game(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS tournament_invitations (id INTEGER PRIMARY KEY AUTOINCREMENT, tournament_id INTEGER, sender_id INTEGER, receiver_id INTEGER, status TEXT, FOREIGN KEY (tournament_id) REFERENCES tournaments(id), FOREIGN KEY (sender_id) REFERENCES users(id), FOREIGN KEY (receiver_id) REFERENCES users(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS matches (id INTEGER PRIMARY KEY AUTOINCREMENT, tournament_id INTEGER, player1_id INTEGER, player2_id INTEGER, result TEXT, FOREIGN KEY (tournament_id) REFERENCES tournaments(id), FOREIGN KEY (player1_id) REFERENCES users(id), FOREIGN KEY (player2_id) REFERENCES users(id))''')
        db.commit()



@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']

        if password != confirm_password:
            flash('Passwords do not match')
            return render_template('register.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            with sqlite3.connect('events3.db') as db:
                cursor = db.cursor()
                cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, role))
                db.commit()
            return redirect(url_for('login'))
        # Handles the case where the username already exists
        except sqlite3.IntegrityError:
            flash('Username already exists')

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('events3.db') as db:
            cursor = db.cursor()
            # Fetch the user from the database
            cursor.execute('SELECT id, username, password, role FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            # Check if the user exists and the password is correct
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]  # user's id
                session['user'] = user[1]  # user's username
                session['role'] = user[3]  # user's role
                # Redirect to the home page
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password')
    return render_template('login.html')



@app.route('/logout')
def logout():
    # Clear the session
    session.pop('user', None)
    return redirect(url_for('home'))


@app.route('/events', methods=['GET'])
def display_events():
    if 'user' not in session:
        flash('You must be logged in to view events')
        return redirect(url_for('login'))

    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()
    user_id = session.get('user_id')
    # Query to select events created by the user or where the user has accepted an invitation
    query = '''
        SELECT DISTINCT e.* FROM events e
        LEFT JOIN user_events ue ON e.id = ue.event_id
        WHERE e.creator_id = ? OR (ue.user_id = ? AND ue.event_id IS NOT NULL)
    '''
    cursor.execute(query, (user_id, user_id))
    events = cursor.fetchall()
    conn.close()

    # Render the events page with the events
    return render_template('display_events.html', events=events)








@app.route('/event_details/<int:event_id>')
def event_details(event_id):
    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    # Fetch the event details
    cursor.execute('SELECT * FROM events WHERE id = ?', (event_id,))
    event = cursor.fetchone()

    # Fetch the attendees of the event
    cursor.execute('''
        SELECT u.id, u.username 
        FROM user_events ue
        JOIN users u ON ue.user_id = u.id
        WHERE ue.event_id = ?
    ''', (event_id,))
    attendees = cursor.fetchall()

    return render_template('event_details.html', event=event, attendees=attendees)






@app.route('/create_event', methods=['GET', 'POST'])
def create_event():
    # Check if the user is logged in and has the role of a user
    if 'user' in session and session['role'] == 'user':
        if request.method == 'POST':
            name = request.form['event_name']
            description = request.form['event_description']
            event_start_time = request.form['event_start_time']
            event_end_time = request.form['event_end_time']
            event_start_time_obj = datetime.strptime(event_start_time, '%Y-%m-%dT%H:%M')
            event_end_time_obj = datetime.strptime(event_end_time, '%Y-%m-%dT%H:%M')
            event_start_time_unix = event_start_time_obj.replace(tzinfo=timezone.utc).timestamp()
            event_end_time_unix = event_end_time_obj.replace(tzinfo=timezone.utc).timestamp()

            conn = sqlite3.connect('events3.db')
            cursor = conn.cursor()

            creator_id = session.get('user_id')

            insert_query = 'INSERT INTO events (name, description, start_date, end_date, creator_id) VALUES (?, ?, ?, ?, ?)'
            cursor.execute(insert_query, (name, description, event_start_time_unix, event_end_time_unix, creator_id))
            conn.commit()

            # Get the ID of the newly created event
            event_id = cursor.lastrowid

            conn.close()
            # Redirect to the details page of the new event
            return redirect(url_for('event_details', event_id=event_id))


        return render_template('create_event.html')







@app.route('/create_tournament', methods=['GET', 'POST'])
def create_tournament():
    # Check if the user is logged in and has the role of a coordinator
    if 'user' in session and session['role'] == 'coordinator':
        # Set the selected game name to None
        selected_game_name = None
        selected_game_id = session.get('selected_game_id')
        # If a game is selected, fetch the game name from the Excel file
        if selected_game_id:
            df = pd.read_excel('1Cleaned_Game_Data.xlsx', engine='openpyxl')
            selected_game = df[df['Game_ID'] == selected_game_id].iloc[0]
            selected_game_name = selected_game['Name']
        # If the form is submitted
        if request.method == 'POST':
            name = request.form['tournament_name']
            description = request.form['tournament_description']
            start_time = request.form['tournament_start_time']
            end_time = request.form['tournament_end_time']
            game_id = selected_game_id


            start_time_obj = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
            end_time_obj = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')
            start_time_unix = start_time_obj.replace(tzinfo=timezone.utc).timestamp()
            end_time_unix = end_time_obj.replace(tzinfo=timezone.utc).timestamp()

            conn = sqlite3.connect('events3.db')
            cursor = conn.cursor()
            creator_id = session.get('user_id')

            insert_query = 'INSERT INTO tournaments (name, description, start_date, end_date, creator_id, game_id) VALUES (?, ?, ?, ?, ?, ?)'
            cursor.execute(insert_query, (name, description, start_time_unix, end_time_unix, creator_id, game_id))
            conn.commit()

            conn.close()
            return redirect(url_for('home'))



        return render_template('create_tournament.html', selected_game_name=selected_game_name)
    else:
        flash('You must be a coordinator to access this page')
        return redirect(url_for('login'))
















def unixtimestampformat(value):
    formatted_date = time.strftime('%H:%M/%d/%m/%Y', time.localtime(value))
    return Markup(formatted_date)

app.jinja_env.filters['unixtimestampformat'] = unixtimestampformat


@app.route('/account')
def account():
    if 'user' not in session:
        flash('You must be logged in to access your account')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    cursor.execute('SELECT id, username, wins FROM users WHERE id = ?', (user_id,))
    user_info = cursor.fetchone()

    cursor.execute('SELECT game_id FROM user_favorites WHERE user_id = ?', (user_id,))
    favorite_game_ids = [row[0] for row in cursor.fetchall()]

    conn.close()

    df = pd.read_excel('1Cleaned_Game_Data.xlsx', engine='openpyxl')
    favorite_games_df = df[df['Game_ID'].isin(favorite_game_ids)]
    favorite_games = favorite_games_df.to_dict('records')

    return render_template('account.html', current_user={'username': user_info[1], 'id': user_info[0], 'wins': user_info[2]}, favorite_games=favorite_games)







@app.route('/search_games', methods=['GET', 'POST'])
def search_games():
    if request.method == 'POST':
        game_name = request.form.get('game_name', '')  # Make sure this matches the name attribute in your form input
        df = pd.read_excel('1Cleaned_Game_Data.xlsx', engine='openpyxl')
        if game_name:  # Check if game_name is not empty
            # Use case-insensitive matching for better search results
            filtered_df = df[df['Name'].str.contains(game_name, case=False, na=False)]
        else:
            # If no search term is provided, return an empty DataFrame or handle accordingly
            filtered_df = pd.DataFrame()
        game_matches = filtered_df.to_dict('records')

        # Check the user's role and render the appropriate template
        if session.get('role') == 'coordinator':
            return render_template('tournament_search_results.html', game_matches=game_matches)
        else:
            # If the user is not a coordinator, render the search results template
            return render_template('search_results.html', game_matches=game_matches)

    return render_template('search_games.html')


@app.route('/send_event_invite/<int:event_id>', methods=['POST'])
def send_event_invite(event_id):
    # Check if the user is logged in
    user_id = request.form.get('user_id')
    # Get the ID of the user sending the invitation
    sender_id = session.get('user_id')


    with sqlite3.connect('events3.db') as db:
        cursor = db.cursor()
        cursor.execute('INSERT INTO event_invitations (event_id, sender_id, receiver_id, status) VALUES (?, ?, ?, "pending")',
                       (event_id, sender_id, user_id))
        db.commit()


    return redirect(url_for('event_details', event_id=event_id))














@app.route('/notifications')
def notifications():
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view notifications')
        return redirect(url_for('login'))

    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    # Fetch event invitations
    cursor.execute('''
        SELECT 'Event' AS type, events.name, event_invitations.id, event_invitations.status
        FROM event_invitations
        JOIN events ON event_invitations.event_id = events.id
        WHERE event_invitations.receiver_id = ? AND event_invitations.status = 'pending'
    ''', (user_id,))
    event_notifications = cursor.fetchall()

    # Fetch tournament invitations
    cursor.execute('''
        SELECT 'Tournament' AS type, tournaments.name, tournament_invitations.id, tournament_invitations.status
        FROM tournament_invitations
        JOIN tournaments ON tournament_invitations.tournament_id = tournaments.id
        WHERE tournament_invitations.receiver_id = ? AND tournament_invitations.status = 'pending'
    ''', (user_id,))
    tournament_notifications = cursor.fetchall()

    # Fetch friend requests
    cursor.execute('''
        SELECT 'Friend Request' AS type, users.username, friend_requests.id, friend_requests.status
        FROM friend_requests
        JOIN users ON friend_requests.sender_id = users.id
        WHERE friend_requests.receiver_id = ? AND friend_requests.status = 'pending'
    ''', (user_id,))
    friend_requests = cursor.fetchall()

    notifications = event_notifications + tournament_notifications + friend_requests
    conn.close()

    return render_template('notifications.html', notifications=notifications)














@app.route('/send_friend_request', methods=['POST'])
def send_friend_request():
    if 'user' not in session:
        flash('You must be logged in to send friend requests')
        return redirect(url_for('login'))

    receiver_id = request.form.get('receiver_id')
    if not receiver_id:
        return redirect(url_for('friends_list'))


    with sqlite3.connect('events3.db') as db:
        cursor = db.cursor()
        cursor.execute('INSERT INTO friend_requests (sender_id, receiver_id, status) VALUES (?, ?, "pending")',
                       (session['user_id'], receiver_id))
        db.commit()

    return redirect(url_for('friends_list'))





@app.route('/respond_to_friend_request/<int:request_id>', methods=['POST'])
def respond_to_friend_request(request_id):
    response = request.form.get('response')
    if response not in ['accept', 'decline']:
        return redirect(url_for('notifications'))


    with sqlite3.connect('events3.db') as db:
        cursor = db.cursor()
        cursor.execute('UPDATE friend_requests SET status = ? WHERE id = ?', (response, request_id))
        db.commit()


    return redirect(url_for('notifications'))





@app.route('/friends_list')
def friends_list():
    if 'user' not in session:
        flash('You must be logged in to view your friends list')
        return redirect(url_for('login'))

    user_id = session.get('user_id')
    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    # Fetch the friends of the user
    cursor.execute('''
        SELECT u.id, u.username 
        FROM users u
        JOIN friend_requests fr ON u.id = fr.sender_id OR u.id = fr.receiver_id
        WHERE (fr.sender_id = ? OR fr.receiver_id = ?) AND fr.status = 'accept'
        AND u.id != ?
    ''', (user_id, user_id, user_id))

    friends = cursor.fetchall()
    conn.close()

    return render_template('friends_list.html', friends=[{'id': f[0], 'username': f[1]} for f in friends])




@app.route('/favorite_game', methods=['POST'])
def favorite_game():
    if 'user' not in session:
        flash('You must be logged in to favorite games')
        return redirect(url_for('login'))

    user_id = session['user_id']
    game_id = request.form.get('game_id')


    with sqlite3.connect('events3.db') as db:
        cursor = db.cursor()
        # Check if the game is already favorited
        cursor.execute('SELECT id FROM user_favorites WHERE user_id = ? AND game_id = ?', (user_id, game_id))

        cursor.execute('INSERT INTO user_favorites (user_id, game_id) VALUES (?, ?)', (user_id, game_id))
        db.commit()


    return redirect(url_for('search_games'))





@app.route('/friend_account/<int:friend_id>')
def friend_account(friend_id):
    if 'user' not in session:
        flash('You must be logged in to view a friend\'s account')
        return redirect(url_for('login'))

    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    cursor.execute('SELECT id, username, wins FROM users WHERE id = ?', (friend_id,))
    friend_info = cursor.fetchone()

    cursor.execute('SELECT game_id FROM user_favorites WHERE user_id = ?', (friend_id,))
    favorite_game_ids = [row[0] for row in cursor.fetchall()]

    conn.close()

    df = pd.read_excel('1Cleaned_Game_Data.xlsx', engine='openpyxl')
    favorite_games_df = df[df['Game_ID'].isin(favorite_game_ids)]
    favorite_games = favorite_games_df.to_dict('records')

    return render_template('friends_account.html', friend_info=friend_info, favorite_games=favorite_games)







@app.route('/remove_favorite', methods=['POST'])
def remove_favorite():
    if 'user' not in session:
        flash('You must be logged in to remove favorites')
        return redirect(url_for('login'))

    user_id = session['user_id']
    game_id = request.form['game_id']


    with sqlite3.connect('events3.db') as db:
        cursor = db.cursor()
        # Remove the game from user_favorites
        cursor.execute('DELETE FROM user_favorites WHERE user_id = ? AND game_id = ?', (user_id, game_id))
        db.commit()


    return redirect(url_for('account'))









@app.route('/tournaments', methods=['GET'])
def display_tournaments():
    if 'user' not in session:
        flash('You must be logged in to view tournaments')
        return redirect(url_for('login'))

    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    user_id = session.get('user_id')

    # Query to select tournaments either created by the user or where the user has accepted an invitation
    cursor.execute('''
        SELECT DISTINCT t.* FROM tournaments t
        LEFT JOIN tournament_invitations ti ON ti.tournament_id = t.id
        WHERE t.creator_id = ? OR (ti.receiver_id = ? AND ti.status = 'accept')
    ''', (user_id, user_id))

    tournaments = cursor.fetchall()
    conn.close()

    return render_template('display_tournaments.html', tournaments=tournaments)


@app.route('/tournament_details/<int:tournament_id>')
def tournament_details(tournament_id):
    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    # Fetch tournament details
    cursor.execute('SELECT * FROM tournaments WHERE id = ?', (tournament_id,))
    tournament = cursor.fetchone()



    # Fetch attendees of the tournament
    cursor.execute('''
        SELECT u.id, u.username
        FROM user_tournaments ut
        JOIN users u ON ut.user_id = u.id
        WHERE ut.tournament_id = ?
    ''', (tournament_id,))
    attendees = cursor.fetchall()

    # Fetch the selected game for the tournament from the Excel file
    game_id = tournament[6]
    df = pd.read_excel('1Cleaned_Game_Data.xlsx', engine='openpyxl')
    selected_game = df[df['Game_ID'] == game_id].iloc[0]

    game = {
        'Name': selected_game['Name'],
        'Youtube_URL': selected_game['Youtube_URL']
    }

    # Fetch matches for the tournament, including the result
    cursor.execute('''
        SELECT m.id, u1.username, u2.username, m.result
        FROM matches m
        JOIN users u1 ON m.player1_id = u1.id
        JOIN users u2 ON m.player2_id = u2.id
        WHERE m.tournament_id = ?
    ''', (tournament_id,))
    matches = cursor.fetchall()

    conn.close()

    return render_template('tournament_details.html', tournament=tournament, attendees=attendees, game=game, matches=matches)








@app.route('/send_tournament_invite/<int:tournament_id>', methods=['POST'])
def send_tournament_invite(tournament_id):
    user_id = request.form.get('user_id')
    sender_id = session.get('user_id')


    with sqlite3.connect('events3.db') as db:
        cursor = db.cursor()
        cursor.execute('INSERT INTO tournament_invitations (tournament_id, sender_id, receiver_id, status) VALUES (?, ?, ?, "pending")',
                       (tournament_id, sender_id, user_id))
        db.commit()

    return redirect(url_for('tournament_details', tournament_id=tournament_id))


@app.route('/respond_to_invite/<type>/<int:invite_id>', methods=['POST'])
def respond_to_invite(type, invite_id):
    response = request.form.get('response')

    with sqlite3.connect('events3.db') as db:
        cursor = db.cursor()
        if type == 'event':
            # Update the event_invitations status
            cursor.execute('UPDATE event_invitations SET status = ? WHERE id = ?', (response, invite_id))
            db.commit()
            # If the invitation is accepted, add to user_events
            if response == 'accept':
                cursor.execute('SELECT event_id, receiver_id FROM event_invitations WHERE id = ?', (invite_id,))
                event_id, user_id = cursor.fetchone()
                cursor.execute('INSERT INTO user_events (user_id, event_id) VALUES (?, ?)', (user_id, event_id))
                db.commit()

        elif type == 'tournament':
            cursor.execute('UPDATE tournament_invitations SET status = ? WHERE id = ?', (response, invite_id))
            db.commit()
            if response == 'accept':
                cursor.execute('SELECT tournament_id, receiver_id FROM tournament_invitations WHERE id = ?',
                               (invite_id,))
                tournament_id, user_id = cursor.fetchone()
                cursor.execute('INSERT INTO user_tournaments (user_id, tournament_id) VALUES (?, ?)',
                               (user_id, tournament_id))
                db.commit()





    return redirect(url_for('notifications'))








@app.route('/search_games_for_tournament', methods=['GET', 'POST'])
def search_games_for_tournament():
    if request.method == 'POST':
        game_name = request.form.get('game_name', '')
        df = pd.read_excel('1Cleaned_Game_Data.xlsx', engine='openpyxl')
        if game_name:
            filtered_df = df[df['Name'].str.contains(game_name, case=False, na=False)]
        else:
            filtered_df = pd.DataFrame()
        game_matches = filtered_df.to_dict('records')
        return render_template('tournament_search_results.html', game_matches=game_matches)
    return render_template('search_games.html')


@app.route('/select_game', methods=['POST'])
def select_game():
    game_id = request.form.get('game_id')
    session['selected_game_id'] = int(game_id)
    return redirect(url_for('create_tournament'))


@app.route('/create_match/<int:tournament_id>', methods=['GET', 'POST'])
def create_match(tournament_id):
    if 'user' not in session or session.get('role') != 'coordinator':
        flash('You must be a coordinator to access this page')
        return redirect(url_for('login'))

    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    # Fetch attendees of the tournament
    cursor.execute('''
        SELECT u.id, u.username
        FROM user_tournaments ut
        JOIN users u ON ut.user_id = u.id
        WHERE ut.tournament_id = ?
    ''', (tournament_id,))
    attendees = cursor.fetchall()

    if request.method == 'POST':
        player1_id = request.form.get('player1_id')
        player2_id = request.form.get('player2_id')

        cursor.execute('INSERT INTO matches (tournament_id, player1_id, player2_id) VALUES (?, ?, ?)',
                       (tournament_id, player1_id, player2_id))
        conn.commit()
        conn.close()
        return redirect(url_for('tournament_details', tournament_id=tournament_id))

    conn.close()
    return render_template('create_match.html', attendees=attendees, tournament_id=tournament_id)


@app.route('/record_match_result', methods=['POST'])
def record_match_result():


    match_id = request.form.get('match_id')
    tournament_id = request.form.get('tournament_id')
    result = request.form.get('result')
    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    cursor.execute('SELECT player1_id, player2_id FROM matches WHERE id = ?', (match_id,))
    match = cursor.fetchone()

    if match:
        if result == 'tie':
            result_text = "Tie"
        else:
            winner_name, _ = result.split(' won')
            if winner_name == match[1]:
                winner_id = match[0]
            else:
                winner_id = match[1]

            cursor.execute('UPDATE users SET wins = wins + 1 WHERE username = ?', (winner_name,))
            result_text = result

        cursor.execute('UPDATE matches SET result = ? WHERE id = ?', (result_text, match_id))
        conn.commit()
        conn.close()

        return redirect(url_for('tournament_details', tournament_id=tournament_id))








@app.route('/search_users', methods=['GET', 'POST'])
def search_users():
    if request.method == 'POST':
        username = request.form.get('username')
        if not username:
            return redirect(url_for('search_users'))

        conn = sqlite3.connect('events3.db')
        cursor = conn.cursor()

        # Exclude the current user's ID from the results
        cursor.execute("SELECT id, username FROM users WHERE username LIKE ? AND id != ?", ('%' + username + '%', session.get('user_id')))
        users = cursor.fetchall()
        conn.close()

        return render_template('search_users.html', users=users)
    return render_template('search_users.html')















if __name__ == '__main__':
    init_db()
    app.run(debug=True)