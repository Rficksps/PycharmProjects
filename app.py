import datetime
import sqlite3
import time
from datetime import timezone
import pandas as pd


from flask import Flask, render_template, request, redirect, url_for, flash, session
from markupsafe import Markup
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 's3cr3t'

def init_db():
    with app.app_context():
        db = sqlite3.connect('events3.db')  # Use 'events3.db' for events
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, role TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, start_date UNIX TIME, end_date UNIX TIME, description TEXT, creator_id INTEGER)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS invitations (id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, sender_id INTEGER, receiver_id INTEGER, status TEXT, FOREIGN KEY (event_id) REFERENCES events(id), FOREIGN KEY (sender_id) REFERENCES users(id), FOREIGN KEY (receiver_id) REFERENCES users(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_events (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, event_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (event_id) REFERENCES events(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_tournaments (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, tournament_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (tournament_id) REFERENCES tournaments(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS friend_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER, status TEXT, FOREIGN KEY (sender_id) REFERENCES users(id), FOREIGN KEY (receiver_id) REFERENCES users(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS user_favorites (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, game_id INTEGER, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (game_id) REFERENCES game(id))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS tournaments (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, start_date UNIX TIME, end_date UNIX TIME, description TEXT, creator_id INTEGER)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS tournament_invitations (id INTEGER PRIMARY KEY AUTOINCREMENT, tournament_id INTEGER, sender_id INTEGER, receiver_id INTEGER, status TEXT, FOREIGN KEY (tournament_id) REFERENCES tournaments(id), FOREIGN KEY (sender_id) REFERENCES users(id), FOREIGN KEY (receiver_id) REFERENCES users(id))''')

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
            flash('Passwords do not match!', 'danger')
            return render_template('register.html')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            with sqlite3.connect('events3.db') as db:
                cursor = db.cursor()
                cursor.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hashed_password, role))
                db.commit()
            flash('Registered successfully!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')

    return render_template('register.html')



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('events3.db') as db:
            cursor = db.cursor()
            cursor.execute('SELECT id, username, password, role FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]  # user's id
                session['user'] = user[1]  # user's username
                session['role'] = user[3]  # user's role
                return redirect(url_for('home'))
            else:
                flash('Invalid username or password!', 'danger')
    return render_template('login.html')



@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))


@app.route('/events', methods=['GET'])
def display_events():
    if 'user' not in session:
        flash('You must be logged in to view events.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    user_id = session.get('user_id')
    # Select distinct events to avoid duplicates
    query = '''
        SELECT DISTINCT e.* FROM events e
        LEFT JOIN user_events ue ON e.id = ue.event_id
        WHERE e.creator_id = ? OR (ue.user_id = ? AND ue.event_id IS NOT NULL)
    '''
    cursor.execute(query, (user_id, user_id))

    events = cursor.fetchall()
    conn.close()

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

    if event:
        return render_template('event_details.html', event=event, attendees=attendees)
    else:
        flash('Event not found!', 'danger')
        return redirect(url_for('display_events'))




from datetime import datetime

@app.route('/create_event', methods=['GET', 'POST'])
def create_event():
    if 'user' in session and session['role'] == 'user':
        if request.method == 'POST':
            name = request.form['event_name']
            description = request.form['event_description']
            event_start_time = request.form['event_start_time']
            event_end_time = request.form['event_end_time']

            try:
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

                event_id = cursor.lastrowid  # Get the ID of the newly created event

                conn.close()

                flash('Event created successfully!', 'success')
                return redirect(url_for('event_details', event_id=event_id))  # Redirect to the details page of the new event

            except ValueError:
                flash('Invalid event time format!', 'danger')
                return render_template('create_event.html')

        return render_template('create_event.html')
    else:
        flash('You must be a user to access this page.', 'danger')
        return redirect(url_for('login'))





@app.route('/create_tournament', methods=['GET', 'POST'])
def create_tournament():
    if 'user' in session and session['role'] == 'coordinator':
        if request.method == 'POST':
            name = request.form['tournament_name']
            description = request.form['tournament_description']
            start_time = request.form['tournament_start_time']
            end_time = request.form['tournament_end_time']

            try:
                start_time_obj = datetime.strptime(start_time, '%Y-%m-%dT%H:%M')
                end_time_obj = datetime.strptime(end_time, '%Y-%m-%dT%H:%M')
                start_time_unix = start_time_obj.replace(tzinfo=timezone.utc).timestamp()
                end_time_unix = end_time_obj.replace(tzinfo=timezone.utc).timestamp()

                conn = sqlite3.connect('events3.db')
                cursor = conn.cursor()
                creator_id = session.get('user_id')

                insert_query = 'INSERT INTO tournaments (name, description, start_date, end_date, creator_id) VALUES (?, ?, ?, ?, ?)'
                cursor.execute(insert_query, (name, description, start_time_unix, end_time_unix, creator_id))
                conn.commit()

                tournament_id = cursor.lastrowid  # Get the ID of the newly created tournament

                conn.close()
                flash('Tournament created successfully!', 'success')
                return redirect(url_for('home'))  # Redirect to the home page or tournament details page

            except ValueError:
                flash('Invalid tournament time format!', 'danger')
                return render_template('create_tournament.html')

        return render_template('create_tournament.html')
    else:
        flash('You must be a coordinator to access this page.', 'danger')
        return redirect(url_for('login'))













def unixtimestampformat(value):
    formatted_date = time.strftime('%H:%M/%d/%m/%Y', time.localtime(value))
    return Markup(formatted_date)

app.jinja_env.filters['unixtimestampformat'] = unixtimestampformat


@app.route('/account')
def account():
    if 'user' not in session:
        flash('You must be logged in to access your account.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    # Get the user's info
    cursor.execute('SELECT id, username FROM users WHERE id = ?', (user_id,))
    user_info = cursor.fetchone()

    # Get the game IDs of the user's favorite games
    cursor.execute('''
        SELECT game_id
        FROM user_favorites
        WHERE user_id = ?
    ''', (user_id,))
    favorite_game_ids = [row[0] for row in cursor.fetchall()]

    conn.close()

    # Load the full games DataFrame
    df = pd.read_excel('1Cleaned_Game_Data.xlsx', engine='openpyxl')

    # Filter the DataFrame to only include the user's favorite games
    # Assumes there's a 'Game_ID' column in your Excel database
    favorite_games_df = df[df['Game_ID'].isin(favorite_game_ids)]

    # Convert the filtered DataFrame to a list of dictionaries for the template
    favorite_games = favorite_games_df.to_dict('records')

    return render_template('account.html', current_user={'username': user_info[1], 'id': user_info[0]},
                           favorite_games=favorite_games)


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
        return render_template('search_results.html', game_matches=game_matches)

    return render_template('search_games.html')






@app.route('/send_invite/<int:event_id>', methods=['POST'])
def send_invite(event_id):
    if 'user' not in session:
        flash('You must be logged in to send invites.', 'danger')
        return redirect(url_for('login'))

    user_id = request.form.get('user_id')
    sender_id = session.get('user_id')

    if not user_id:
        flash('No user ID provided.', 'danger')
        return redirect(url_for('event_details', event_id=event_id))

    try:
        with sqlite3.connect('events3.db') as db:
            cursor = db.cursor()
            cursor.execute('INSERT INTO invitations (event_id, sender_id, receiver_id, status) VALUES (?, ?, ?, ?)',
                           (event_id, sender_id, user_id, 'pending'))
            db.commit()
        flash('Invitation sent successfully.', 'success')
    except Exception as e:
        flash(str(e), 'danger')

    return redirect(url_for('event_details', event_id=event_id))





@app.route('/notifications')
def notifications():
    user_id = session.get('user_id')

    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    # Get event invitations
    cursor.execute('''
        SELECT 'Event' AS type, events.name, invitations.id, invitations.status
        FROM invitations 
        JOIN events ON invitations.event_id = events.id 
        WHERE invitations.receiver_id = ? AND invitations.status = 'pending'
    ''', (user_id,))

    event_notifications = cursor.fetchall()

    # Get friend requests
    cursor.execute('''
        SELECT 'Friend Request' AS type, users.username, friend_requests.id, friend_requests.status
        FROM friend_requests
        JOIN users ON friend_requests.sender_id = users.id
        WHERE friend_requests.receiver_id = ? AND friend_requests.status = 'pending'
    ''', (user_id,))

    friend_notifications = cursor.fetchall()

    cursor.execute('''
           SELECT 'Tournament' AS type, tournaments.name, tournament_invitations.id, tournament_invitations.status
           FROM tournament_invitations
           JOIN tournaments ON tournament_invitations.tournament_id = tournaments.id
           WHERE tournament_invitations.receiver_id = ? AND tournament_invitations.status = 'pending'
       ''', (user_id,))
    tournament_notifications = cursor.fetchall()

    # Combine notifications
    notifications = event_notifications + friend_notifications + tournament_notifications
    conn.close()

    return render_template('notifications.html', notifications=notifications)




@app.route('/respond_to_invite/<int:invite_id>', methods=['POST'])
def respond_to_invite(invite_id):
    response = request.form.get('response')
    if response not in ['accept', 'decline']:
        flash('Invalid response.', 'danger')
        return redirect(url_for('notifications'))

    try:
        with sqlite3.connect('events3.db') as db:
            cursor = db.cursor()
            cursor.execute('UPDATE invitations SET status = ? WHERE id = ?', (response, invite_id))
            if response == 'accept':
                cursor.execute('SELECT event_id FROM invitations WHERE id = ?', (invite_id,))
                event_id = cursor.fetchone()[0]
                cursor.execute('INSERT INTO user_events (user_id, event_id) VALUES (?, ?)', (session['user_id'], event_id))
            db.commit()
        flash(f'Invitation {response}ed.', 'success')
    except Exception as e:
        flash(str(e), 'danger')

    return redirect(url_for('notifications'))





@app.route('/send_friend_request', methods=['POST'])
def send_friend_request():
    if 'user' not in session:
        flash('You must be logged in to send friend requests.', 'danger')
        return redirect(url_for('login'))

    receiver_id = request.form.get('receiver_id')
    if not receiver_id:
        flash('No user ID provided.', 'danger')
        return redirect(url_for('friends_list'))

    try:
        with sqlite3.connect('events3.db') as db:
            cursor = db.cursor()
            cursor.execute('INSERT INTO friend_requests (sender_id, receiver_id, status) VALUES (?, ?, "pending")',
                           (session['user_id'], receiver_id))
            db.commit()
        flash('Friend request sent successfully.', 'success')
    except Exception as e:
        flash(str(e), 'danger')

    return redirect(url_for('friends_list'))





@app.route('/respond_to_friend_request/<int:request_id>', methods=['POST'])
def respond_to_friend_request(request_id):
    response = request.form.get('response')
    if response not in ['accept', 'decline']:
        flash('Invalid response.', 'danger')
        return redirect(url_for('notifications'))

    try:
        with sqlite3.connect('events3.db') as db:
            cursor = db.cursor()
            cursor.execute('UPDATE friend_requests SET status = ? WHERE id = ?', (response, request_id))
            db.commit()
        flash(f'Friend request {response}ed.', 'success')
    except Exception as e:
        flash(str(e), 'danger')

    return redirect(url_for('notifications'))





@app.route('/friends_list')
def friends_list():
    if 'user' not in session:
        flash('You must be logged in to view your friends list.', 'danger')
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
        flash('You must be logged in to favorite games.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    game_id = request.form.get('game_id')

    try:
        with sqlite3.connect('events3.db') as db:
            cursor = db.cursor()
            # Check if the game is already favorited
            cursor.execute('SELECT id FROM user_favorites WHERE user_id = ? AND game_id = ?', (user_id, game_id))
            if cursor.fetchone():
                flash('You have already favorited this game.', 'info')
            else:
                cursor.execute('INSERT INTO user_favorites (user_id, game_id) VALUES (?, ?)', (user_id, game_id))
                db.commit()
                flash('Game added to favorites.', 'success')
    except Exception as e:
        flash('Error adding game to favorites.', 'danger')
        print(e)

    return redirect(url_for('search_games'))





@app.route('/friend_account/<int:friend_id>')
def friend_account(friend_id):
    if 'user' not in session:
        flash('You must be logged in to view a friend\'s account.', 'danger')
        return redirect(url_for('login'))

    # Assuming friend_id is the user ID of the friend
    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    # Get the friend's info
    cursor.execute('SELECT id, username FROM users WHERE id = ?', (friend_id,))
    friend_info = cursor.fetchone()

    # Get the game IDs of the friend's favorite games
    cursor.execute('''
        SELECT game_id
        FROM user_favorites
        WHERE user_id = ?
    ''', (friend_id,))
    favorite_game_ids = [row[0] for row in cursor.fetchall()]

    conn.close()

    # Load the full games DataFrame
    df = pd.read_excel('1Cleaned_Game_Data.xlsx', engine='openpyxl')

    # Filter the DataFrame to only include the friend's favorite games
    favorite_games_df = df[df['Game_ID'].isin(favorite_game_ids)]
    favorite_games = favorite_games_df.to_dict('records')

    return render_template('friends_account.html', friend_info=friend_info, favorite_games=favorite_games)







@app.route('/remove_favorite', methods=['POST'])
def remove_favorite():
    if 'user' not in session:
        flash('You must be logged in to remove favorites.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    game_id = request.form['game_id']

    try:
        with sqlite3.connect('events3.db') as db:
            cursor = db.cursor()
            # Remove the game from user_favorites
            cursor.execute('DELETE FROM user_favorites WHERE user_id = ? AND game_id = ?', (user_id, game_id))
            db.commit()
            flash('Game removed from favorites.', 'success')
    except Exception as e:
        flash('Error removing game from favorites.', 'danger')
        print(e)

    return redirect(url_for('account'))






@app.route('/search_users', methods=['POST'])
def search_users():
    username = request.form.get('username')
    if not username:
        flash('Please enter a username.', 'danger')
        return redirect(url_for('friends_list'))

    user_id = session.get('user_id')  # Retrieve current user's ID from session
    if not user_id:
        flash('You must be logged in to perform this action.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()
    # Exclude the current user's ID from the results
    cursor.execute("SELECT id, username FROM users WHERE username LIKE ? AND id != ?", ('%' + username + '%', user_id))
    users = cursor.fetchall()
    conn.close()

    return render_template('search_users.html', users=users)









@app.route('/tournaments', methods=['GET'])
def display_tournaments():
    if 'user' not in session:
        flash('You must be logged in to view tournaments.', 'danger')
        return redirect(url_for('login'))

    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    user_id = session.get('user_id')
    # Select tournaments created by the logged-in user
    cursor.execute('SELECT * FROM tournaments WHERE creator_id = ?', (user_id,))

    tournaments = cursor.fetchall()
    conn.close()

    return render_template('display_tournaments.html', tournaments=tournaments)








@app.route('/tournament_details/<int:tournament_id>')
def tournament_details(tournament_id):
    conn = sqlite3.connect('events3.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM tournaments WHERE id = ?', (tournament_id,))
    tournament = cursor.fetchone()

    cursor.execute('''
        SELECT u.id, u.username 
        FROM user_tournaments ut
        JOIN users u ON ut.user_id = u.id
        WHERE ut.tournament_id = ?
    ''', (tournament_id,))
    participants = cursor.fetchall()

    if tournament:
        return render_template('tournament_details.html', tournament=tournament, participants=participants)
    else:
        flash('Tournament not found!', 'danger')
        return redirect(url_for('display_tournaments'))







@app.route('/send_tournament_invite/<int:tournament_id>', methods=['POST'])
def send_tournament_invite(tournament_id):
    user_id = request.form.get('user_id')
    sender_id = session.get('user_id')

    try:
        with sqlite3.connect('events3.db') as db:
            cursor = db.cursor()
            cursor.execute('INSERT INTO tournament_invitations (tournament_id, sender_id, receiver_id, status) VALUES (?, ?, ?, "pending")',
                           (tournament_id, sender_id, user_id))
            db.commit()
        flash('Invitation sent successfully.', 'success')
    except Exception as e:
        flash(str(e), 'danger')
    return redirect(url_for('tournament_details', tournament_id=tournament_id))











if __name__ == '__main__':
    init_db()
    app.run(debug=True)