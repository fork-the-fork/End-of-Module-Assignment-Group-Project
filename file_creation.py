import pickle
import json

list_1 = [1, 2, 3, 4, 5, 6]

dict_1 = {'A': 'Hello', 'B': 'My name is', 'C': 'Azmi'}

with open('list_1.pkl', 'wb') as pickle_file:
    pickle.dump(list_1, pickle_file)

with open('dict_1.pkl', 'wb') as pickle_file:
    pickle.dump(dict_1, pickle_file)

with open('list_1.json', 'w') as json_file:
    json.dump(dict_1, json_file)

with open('dict_1.json', 'w') as json_file:
    json.dump(dict_1, json_file)