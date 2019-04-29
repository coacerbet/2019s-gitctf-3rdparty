# 3rdParty CA
This is the **3rdParty** CA (Certificate Authority).

## Usage

### Run the server
`./run.sh`

### Connect to the server
- with `curl`  
`curl -d "uid=dohki&passwd=1234" localhost:5000/user/login`
- with `python requests`  
  Check out [test](https://github.com/KAIST-IS521/2019s-3rdparty/tree/master/test).
