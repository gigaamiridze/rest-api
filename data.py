# Test database
from app import db, UserModel, VaccinationModel

db.create_all()

user_data = [
    {'id': 1, 'email': 'justttfelix@gmail.com', 'password': 'justfelix'},
    {'id': 2, 'email': 'snapelilith@gmail.com', 'password': 'nausicaa'},
    {'id': 3, 'email': 'maxime@gmail.com', 'password': 'kayakata'},
    {'id': 4, 'email': 'travis@gmail.com', 'password': 'jackboys'},
    {'id': 5, 'email': 'toliver@gmail.com', 'password': 'heaven_or_hell'},
]

vaccination_date = [
    {'id': 1, 'name': 'Giga', 'surname': 'Amiridze', 'age': 18, 'vaccine_type': 'Sinovac', 'dose': 1, 'date': '20 May, 2021', 'user_id': 1},
    {'id': 2, 'name': 'Mariam', 'surname': 'Mukhadgverdeli', 'age': 24, 'vaccine_type': 'Sinovac', 'dose': 3, 'date': '28 January, 2021', 'user_id': 2},
    {'id': 3, 'name': 'Maxime', 'surname': 'Machaidze', 'age': 25, 'vaccine_type': 'Pfizer', 'dose': 3, 'date': '7 May, 2021', 'user_id': 3},
    {'id': 4, 'name': 'Travis', 'surname': 'Scott', 'age': 28, 'vaccine_type': 'Moderna', 'dose': 3, 'date': '14 February, 2021', 'user_id': 4},
    {'id': 5, 'name': 'Don', 'surname': 'Toliver', 'age': 27, 'vaccine_type': 'AstraZeneca', 'dose': 2, 'date': '7 July, 2021', 'user_id': 5},
]

def create_database():
    for i in user_data:
        user = UserModel(email=i['email'], password=i['password'])
        db.session.add(user)
        db.session.commit()

    for i in vaccination_date:
        vaccine = VaccinationModel(name=i['name'], surname=i['surname'], age=i['age'], vaccine_type=i['vaccine_type'], dose=i['dose'], date=i['date'], user_id=i['user_id'])
        db.session.add(vaccine)
        db.session.commit()

if __name__ == '__main__':
    create_database()