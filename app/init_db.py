from app.database import Base, engine
from app.models import User


Base.metadata.drop_all(bind=engine)


Base.metadata.create_all(bind=engine)

print("Таблицы созданы заново!")
