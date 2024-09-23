import joblib  # Pour charger le modèle pré-entrainé
import numpy as np

# Charger le modèle XGBoost
model = joblib.load('model/xgboost_model.pkl')

# Charger le label encoder pour convertir les prédictions en 'normal' et 'attack'
le = joblib.load('model/label_encoder.pkl')
