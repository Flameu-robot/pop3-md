# 1.
git clone https://github.com/Flameu-robot/pop3-md.git
cd pop3-md

# 2. 
sudo apt-get update
sudo apt-get install -y libssl-dev

# 3. 
gcc -Wall -Wextra -o client src/client.c -lssl -lcrypto

# 4.
./client xxx@gmail.com "xxxx xxxx xxxx xxxx"