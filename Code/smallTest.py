# from u20453508_Prac_3_Backend import *
from oldCode import *


def smallTest():
    message = "abc"
    temp1 = sha_String_To_Hex(message)
    temp2 = sha_Preprocess_Message(temp1)
    temp3 = sha_Message_Schedule(temp2)
    temp4 = sha_Hash_Round_Function(temp2,
                                    "6A09E667F3BCC908",
                                    "BB67AE8584CAA73B",
                                    "3C6EF372FE94F82B",
                                    "A54FF53A5F1D36F1",
                                    "510E527FADE682D1",
                                    "9B05688C2B3E6C1F",
                                    "1F83D9ABFB41BD6B",
                                    "5BE0CD19137E2179",
                                    "428a2f98d728ae22")
    temp5 = sha_F_Function(temp2,
                           "6A09E667F3BCC908",
                           "BB67AE8584CAA73B",
                           "3C6EF372FE94F82B",
                           "A54FF53A5F1D36F1",
                           "510E527FADE682D1",
                           "9B05688C2B3E6C1F",
                           "1F83D9ABFB41BD6B",
                           "5BE0CD19137E2179")
    temp6 = sha_Process_Message_Block(temp2,
                                      "6A09E667F3BCC908",
                                      "BB67AE8584CAA73B",
                                      "3C6EF372FE94F82B",
                                      "A54FF53A5F1D36F1",
                                      "510E527FADE682D1",
                                      "9B05688C2B3E6C1F",
                                      "1F83D9ABFB41BD6B",
                                      "5BE0CD19137E2179")

    ans = f"temp1: {temp1} \n" + f"temp2: {temp2} \n" + f"temp3: {temp3} \n" + f"temp4: {temp4} \n" + (
        f"temp5: {temp5} \n") + f"temp6: {temp6}"

    with open("temp.txt", 'w') as file:
        file.write(ans)
