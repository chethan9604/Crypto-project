from flask import Flask, render_template, request
app = Flask(__name__)
app.config.from_object(__name__)


@app.route('/')
def welcome():
    return render_template('form.html')


@app.route('/', methods=['POST'])
def result():
    plainText =request.form.get("var_1", type=str)
    key = request.form.get("var_2", type=str)
    if request.form['submit_button'] == 'Encryption':
        k=encrypt(plainText,key)
    else:
        k=decrypt(plainText,key)
    return render_template('form.html',inp=plainText,entry=key, entry1=k)
def encrypt(plainText,key):
    dup=plainText
    dup1=key
    initialState = []
    initialKey = []
    finalState = []
    total = 0
    plainText=plainText.split(" ")
    key=key.split(" ")
    print(key)
    for i in range(4):
        temp =[]
        temp1=[]
        temp2 =[]
        for j in range(4):
            temp.append(plainText[total])
            temp1.append(plainText[total])
            temp2.append(key[total])
            total+=1
        initialState.append(temp)
        initialKey.append(temp2)
        finalState.append(temp1)
    print("--------Initial----------")
    print(initialKey)
    print("Initial Plain text Matrix")
    printMatrix(initialState)
    print("Initial Key matrix")
    print(initialKey)
    printMatrix(initialKey)
    print("-------------------------")
    initialState=addRoundKey(initialState,initialKey)
    print("initial state")
    print(initialState)
    for i in range(1,11):
        print("--------Round "+str(i)+"---------")
        print("This round Key")
        initialKey = keyExpansion(initialKey,i,rci,sbox)
        printMatrix(initialKey)
        print("After Susbstitution")
        initialState = substitute(initialState,sbox)
        printMatrix(initialState)

        print("After shift rows")
        initialState = shiftRow(initialState)
        printMatrix(initialState)
        if(i!=10):
            print("After Mix column")
            initialState = mixCCol(initialState)
            printMatrix(initialState)
        #print("After key expansion")
        #print(initialKey)
        print("After add round key")
        initialState = addRoundKey(initialState,initialKey)
        printMatrix(initialState)
    print("-----------Result----------")
    print("Original Message")
    printMatrix(finalState)
    initialState=removehexa(initialState)
    print("The cipher text is")
    ar=""
    for i in initialState:
        ar+=" ".join(i)
        ar+=" "
    print(ar)
    return ar

def decrypt(plainText,key):
    dup=plainText
    dup1=key
    initialState = []
    initialKey = []
    finalState = []
    total = 0
    plainText=plainText.split(" ")
    key=key.split(" ")
    print(key)
    for i in range(4):
        temp =[]
        temp1=[]
        temp2 =[]
        for j in range(4):
            temp.append(plainText[total])
            temp1.append(plainText[total])
            temp2.append(key[total])
            total+=1
        initialState.append(temp)
        initialKey.append(temp2)
        finalState.append(temp1)
    print("--------Initial----------")
    print(initialKey)
    print("Initial Plain text Matrix")
    printMatrix(initialState)
    print("Initial Key matrix")
    print(initialKey)
    printMatrix(initialKey)
    print("-------------------------")
    print("--------Initial----------")
    print("Initial Plain text Matrix")
    print(initialKey)
    printMatrix(initialState)
    print("Initial Key matrix")
    printMatrix(initialKey)
    print("-------------------------")
    init=initialKey
    print("===============================================================================")
    print(init)
    ar=[]
    for i in range(1,11):
        initialKey=keyExpansion(initialKey,i,rci,sbox)
        ar.append(initialKey)
    print(ar[9])
    initialState=addRoundKey(initialState,ar[9])
    print("initial state")
    printMatrix(initialState)
    for i in range(1,11):
        print("--------Round "+str(i)+"---------")
        initialState = rightshift(initialState)
        print("After shift rows")
        printMatrix(initialState)
        print("After Susbstitution")
        initialState = Substitute(initialState,sinverse)
        print(initialState)
        print("After key expansion")
        if(i==10):
            print(init)
            initialState=addRoundKey(initialState,init)
        else:
            print(ar[10-i-1])
            initialState=addRoundKey(initialState,ar[i-1])
        printMatrix(initialState)
        if(i!=10):
            print("After Mix column")
            initialState = mixCol(initialState)
            printMatrix(initialState)
        printMatrix(initialState)
    print("-----------Result----------")
    print("Original Message")
    printCipher(finalState)
    print("The cipher text is")
    printCipher(initialState)
    initialState=removehexa(initialState)
    ar=""
    for i in initialState:
        ar+=" ".join(i)
        ar+=" "
    print(ar)
    return ar



def printMatrix(m):
    for i in range(4):
        for j in range(4):
            y = m[i][j]
            if(y == "0x00"):
                y = "00"
            elif(len(y.lstrip("0x")) <= 1):
                y = "0"+y.lstrip("0x")
            else:
                y = y.lstrip("0x")
            print(y.upper(),end=" ")
        print(" ")
def printCipher(m):
    for i in range(4):
        for j in range(4):
            y = m[i][j]
            if(y == "0x00"):
                y = "00"
            elif(len(y.lstrip("0x")) <= 1):
                y = "0"+y.lstrip("0x")
            else:
                y = y.lstrip("0x")
            print(y.upper(),end=" ")
    print(" ")
def removehexa(ar):
    for i in range(4):
        for j in range(4):
            ar[i][j]=ar[i][j].lstrip("0x")
    return ar
def keyExpansion(key,numround,rci,s_box):
    round_const = rci[numround-1]
    gw3 = [key[1][3],key[2][3],key[3][3],key[0][3]]
    print("gw3")
    print(gw3)
    for i in range(4):
        if(numround>1):
            u = hex(s_box[int(gw3[i][2],16)][int(gw3[i][3],16)])
        else:
            u = hex(s_box[int(gw3[i][0],16)][int(gw3[i][1],16)])
        print(u)
        if(u == "0x0"):
            u = "0x00"
        elif(len(u.lstrip("0x"))<=1):
            u = "0x0"+u.lstrip("0x")
        gw3[i] = u
    a = 1
    b = 1
    if(gw3[0] == "0x00" or gw3[0] == "0x0"):
        a = 0
    else:
        a = int(gw3[0].lstrip("0x"),16)
    print(a)
    x = hex(int(a^int(round_const.lstrip("0x"),16)))
    print(x)
    if(x == "0x0"):
        x = "0x00"
    elif(len(x.lstrip("0x"))<=1):
        x = "0x0"+x.lstrip("0x")
    gw3[0] = x
    print(gw3)
    w4 = []
    for i in range(4):
        r = 1
        p = 1
        if(gw3[i] == "0x00" or gw3[i] == "0x0"):
            r = 0
        else:
            r = int(gw3[i].lstrip("0x"),16)
        if(key[i][0] == "0x00" or key[i][0] == "0x0"):
            p = 0
        else:
            p = int(key[i][0].lstrip("0x"),16)
        y = hex(r^p)
        if(y == "0x0"):
            y = "0x00"
        elif(len(y.lstrip("0x")) <= 1):
            y = "0x0"+y.lstrip("0x")
        w4.append(y)
    print(w4)
    w5 = []
    w6 = []
    w7 = []
    for i in range(4):
        r = 1
        p = 1
        if(w4[i] == "0x00" or w4[i] == "0x0"):
            r = 0
        else:
            r = int(w4[i].lstrip("0x"),16)
        if(key[i][1] == "0x00" or key[i][1] == "0x0"):
            p = 0
        else:
            p = int(key[i][1].lstrip("0x"),16)
        y = hex(r^p)
        if(y == "0x0"):
            y = "0x00"
        elif(len(y.lstrip("0x")) <= 1):
            y = "0x0"+y.lstrip("0x")
        w5.append(y)
    for i in range(4):
        r = 1
        p = 1
        if(w5[i] == "0x00" or w5[i] == "0x0"):
            r = 0
        else:
            r = int(w5[i].lstrip("0x"),16)
        if(key[i][2] == "0x00" or key[i][2] == "0x0"):
            p = 0
        else:
            p = int(key[i][2].lstrip("0x"),16)
        y = hex(r^p)
        if(y == "0x0"):
            y = "0x00"
        elif(len(y.lstrip("0x")) <= 1):
            y = "0x0"+y.lstrip("0x")
        w6.append(y)
    for i in range(4):
        r = 1
        p = 1
        if(w6[i] == "0x00" or w6[i] == "0x0"):
            r = 0
        else:
            r = int(w6[i].lstrip("0x"),16)
        if(key[i][3] == "0x00" or key[i][3] == "0x0"):
            p = 0
        else:
            p = int(key[i][3].lstrip("0x"),16)
        y = hex(r^p)
        if(y == "0x0"):
            y = "0x00"
        elif(len(y.lstrip("0x")) <= 1):
            y = "0x0"+y.lstrip("0x")
        w7.append(y)
    cr=[w4,w5,w6,w7]
    br=[]
    for i in range(4):
        ar=[]
        for j in range(4):
            ar.append(cr[j][i])
        br.append(ar)
    return br
def addRoundKey(pt,rk):
    for i in range(4):
        for j in range(4):
            x = 0
            y = 0
            if(pt[j][i] != "0x00" and pt[j][i]!="0x0"):
                x = int(pt[j][i].lstrip("0x"),16)
            if(rk[j][i] != "0x00" and rk[j][i]!="0x0"):
                y = int(rk[j][i].lstrip("0x"),16)
            z = hex(x^y)
            if(z == "0x0"):
                z = "0x00"
            elif(len(z.lstrip("0x")) <= 1):
                z = "0x0"+z.lstrip("0x")
            pt[j][i] = z
    return pt

def Substitute(pt,s_box):
    for i in range(4):
        for j in range(4):
            if(pt[i][j] == "0x0"):
                pt[i][j] = "0x00"
            elif(len(pt[i][j].lstrip("0x"))<=1):
                pt[i][j] = "0x0"+pt[i][j].lstrip("0x")
            u = hex(s_box[int(pt[i][j][2],16)][int(pt[i][j][3],16)])
            if(u == "0x0"):
                u = "0x00"
            elif(len(u.lstrip("0x"))<=1):
                u = "0x0"+u.lstrip("0x")
            pt[i][j] = u
    return pt
def substitute(pt,s_box):
    for i in range(4):
        for j in range(4):
            u = hex(s_box[int(pt[i][j][2],16)][int(pt[i][j][3],16)])
            if(u == "0x0"):
                u = "0x00"
            elif(len(u.lstrip("0x"))<=1):
                u = "0x0"+u.lstrip("0x")
            pt[i][j] = u
    return pt
def shiftRow(pt):
    pt[1][0],pt[1][1],pt[1][2],pt[1][3] = pt[1][1],pt[1][2],pt[1][3],pt[1][0]
    pt[2][0],pt[2][1],pt[2][2],pt[2][3] = pt[2][2],pt[2][3],pt[2][0],pt[2][1]
    pt[3][0],pt[3][1],pt[3][2],pt[3][3] = pt[3][3],pt[3][0],pt[3][1],pt[3][2]
    return pt
def rightshift(pt):
    pt[1][0],pt[1][1],pt[1][2],pt[1][3] = pt[1][3],pt[1][0],pt[1][1],pt[1][2]
    pt[2][0],pt[2][1],pt[2][2],pt[2][3] = pt[2][2],pt[2][3],pt[2][0],pt[2][1]
    pt[3][0],pt[3][1],pt[3][2],pt[3][3] = pt[3][1],pt[3][2],pt[3][3],pt[3][0]
    return pt

def mixColumns(a, b, c, d):
    i=hex(gmul(a, 2) ^ gmul(b, 3) ^ gmul(c, 1) ^ gmul(d, 1))
    j=hex(gmul(a, 1) ^ gmul(b, 2) ^ gmul(c, 3) ^ gmul(d, 1))
    k=hex(gmul(a, 1) ^ gmul(b, 1) ^ gmul(c, 2) ^ gmul(d, 3))
    l=hex(gmul(a, 3) ^ gmul(b, 1) ^ gmul(c, 1) ^ gmul(d, 2))
    print(i,j,k,l)
    return [i,j,k,l]

def gmul(a, b):
    if b == 1:
        return a
    tmp = (a << 1) & 0xff
    if b == 2:
        return tmp if a < 128 else tmp ^ 0x1b
    if b == 3:
        return gmul(a, 2) ^ a
def printHex(val):
    return '{:02x}'.format(val)
def mixCCol(pt):
    res = []
    for i in range(4):
        ar=[]
        for j in range(4):
            k=int(pt[j][i],16)
            ar.append(k)
        print(ar)
        res.append(mixColumns(ar[0],ar[1],ar[2],ar[3]))
    br=[]
    for i in range(4):
        ar=[]
        for j in range(4):
            ar.append(res[j][i])
        br.append(ar)
        print(ar)
    return br
sbox=[[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
   [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
   [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
   [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
   [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
   [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
   [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
   [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
   [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
   [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
   [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
   [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
   [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
   [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
   [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
   [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]
sinverse=[[0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]]
def galoisMult(a, b):
    p = 0
    hiBitSet = 0
    for i in range(8):
        if b & 1 == 1:
            p ^= a
        hiBitSet = a & 0x80
        a <<= 1
        if hiBitSet == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256

def mixcolumns(a, b, c, d):
    i=hex(galoisMult(a, 14) ^ galoisMult(b, 11) ^ galoisMult(c, 13) ^ galoisMult(d, 9))
    j=hex(galoisMult(a, 9) ^ galoisMult(b, 14) ^ galoisMult(c, 11) ^ galoisMult(d, 13))
    k=hex(galoisMult(a, 13) ^ galoisMult(b, 9) ^ galoisMult(c, 14) ^ galoisMult(d, 11))
    l=hex(galoisMult(a, 11) ^ galoisMult(b, 13) ^ galoisMult(c, 9) ^ galoisMult(d, 14))
    print(i,j,k,l)
    return [i,j,k,l]
def mixCol(pt):
    res = []
    for i in range(4):
        ar=[]
        for j in range(4):
            k=int(pt[j][i],16)
            ar.append(k)
        print(ar)
        res.append(mixcolumns(ar[0],ar[1],ar[2],ar[3]))
    br=[]
    for i in range(4):
        ar=[]
        for j in range(4):
            ar.append(res[j][i])
        br.append(ar)
        print(ar)
    return br

rci = ["0x01","0x02","0x04","0x08","0x10","0x20","0x40","0x80","0x1B","0x36"]
##main

if __name__ == '__main__':
    app.run(debug=True)
