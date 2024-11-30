NEED TO DO
///////////////////
create sql table with:
-first name (string)
-last name (string)
-gender (bool)
-weight (flaoitng)
-height (floating)
-health history (text)
///////////////////
-use sql database (done)
///////////////////
-have username and password for user authentication (first screen works for this)
-dont store original password in cloud (i believe done)
///////////////////
-Set permissions for users 
-group h can access everything while r can see everything but name
-only h can add to database and modify patients
///////////////////
Basic query integrity protection. The system should allow a user to detect modified query results.
– Single data item integrity (5 pts). If a returned data item is modified or fake, the user should be
able to detect. Make sure consider users from both groups.
– Query completeness (5 pts). If the one or more data items are removed from a query result, the
user should be able to detect, at least with a probability
///////////////////
gender and age are sensitive and should be protected (encrypted????)
///////////////////
add to git
and make project report
//////////////////

HOW TO RUN
1. paste "set TEST_MASTER_KEY=super_secure_master_key" in terminal (can set as any key but must delete db or set database name to a new name for the key)
2. python main.py in terminal
3. can log into database with username test and password pass for h permissions and can log in with test2 as username and pass as password for r permissions (only 2 pass and usernames that works every time)



1. download vscode extension sqlite by alex
2. should then show up in bottom left otherwise do control shift p when on database you want to open and paste 'SQLite: Open Database' in the search and then it should work
3. if it works it will show in bottom left and say sqlite explorer
4. open to a table and hit left arrow to open up the db (it will open in split window)


can log into database with username test and password pass for h permissions and can log in with test2 as username and pass as password for r permissions (only 2 pass and usernames that works every time)
