# model_training.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score, roc_auc_score
import xgboost as xgb
import pickle
import matplotlib.pyplot as plt
import seaborn as sns

class IAMRiskModel:
    """Train and evaluate risk prediction model"""
    
    def __init__(self):
        self.model = None
        self.feature_names = None
        
    def prepare_data(self, df: pd.DataFrame):
        """Prepare features and labels"""
        
        # Drop non-feature columns
        drop_cols = ['policy_id', 'risk_label', 'prob_low', 'prob_medium', 'prob_high']
        X = df.drop(columns=[c for c in drop_cols if c in df.columns])
        
        # Use hard labels as targets
        y = df['risk_label'].values
        
        # Store feature names
        self.feature_names = X.columns.tolist()
        
        return X, y
    
    def train_baseline(self, X_train, y_train):
        """Train simple baseline for comparison"""
        
        # Rule-based baseline
        def rule_based_predict(X):
            preds = []
            for idx, row in X.iterrows():
                score = 0
                
                if row['escalation_path_count'] > 0:
                    score += 3
                if row['has_wildcard_action'] == 1:
                    score += 2
                if row['dangerous_action_count'] > 3:
                    score += 2
                if row['min_escalation_path_length'] <= 2:
                    score += 3
                    
                if score >= 7:
                    preds.append(2)  # HIGH
                elif score >= 3:
                    preds.append(1)  # MEDIUM
                else:
                    preds.append(0)  # LOW
                    
            return np.array(preds)
        
        return rule_based_predict
    
    def train_random_forest(self, X_train, y_train):
        """Train Random Forest model"""
        
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=10,
            min_samples_leaf=5,
            class_weight='balanced',
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        return self.model
    
    def train_gradient_boosting(self, X_train, y_train):
        """Train Gradient Boosting model"""
        
        self.model = GradientBoostingClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            subsample=0.8,
            random_state=42
        )
        
        self.model.fit(X_train, y_train)
        return self.model
    
    def train_xgboost(self, X_train, y_train):
        """Train XGBoost model (best for tabular data)"""
        
        self.model = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            objective='multi:softmax',
            num_class=3,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_train, y_train)
        return self.model
    
    def evaluate(self, X_test, y_test):
        """Comprehensive evaluation"""
        
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)
        
        print("="*60)
        print("MODEL EVALUATION REPORT")
        print("="*60)
        
        # Classification report
        print("\nClassification Report:")
        print(classification_report(
            y_test, y_pred,
            labels=np.unique(y_test),  # Auto-detect actual classes present
            digits=4
        ))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print("\nConfusion Matrix:")
        print(cm)
        
        # Per-class metrics
        from sklearn.metrics import precision_recall_fscore_support
        precision, recall, f1, support = precision_recall_fscore_support(y_test, y_pred)
        
        print("\nPer-Class Metrics:")
        unique_classes = np.unique(y_test)
        for i, class_id in enumerate(unique_classes):
            risk_level = ['Low', 'Medium', 'High'][class_id]
            print(f"{risk_level} Risk:")
            print(f"  Precision: {precision[i]:.4f}")
            print(f"  Recall:    {recall[i]:.4f}")
            print(f"  F1-Score:  {f1[i]:.4f}")
            print(f"  Support:   {support[i]}")
        
        # High-risk focus (if class exists)
        print("\n=== HIGH-RISK CLASS ANALYSIS ===")
        unique_classes = np.unique(y_test)
        if 2 in unique_classes:
            high_risk_precision = precision[2]
            high_risk_recall = recall[2]
            fn_high = sum((y_test == 2) & (y_pred != 2))
            fp_high = sum((y_test != 2) & (y_pred == 2))
            print(f"Precision: {high_risk_precision:.4f}")
            print(f"Recall:    {high_risk_recall:.4f}")
            print(f"False Negatives: {fn_high}")
            print(f"False Positives: {fp_high}")
        else:
            print("No high-risk examples in test set (conservative labeling)")

        
        # False negatives (missed threats - BAD)
        fn_high = sum((y_test == 2) & (y_pred != 2))
        if sum(y_test == 2) > 0:
            print(f"FN Rate: {fn_high / sum(y_test == 2):.2%}")
        else:
            print("FN Rate: N/A (no high-risk ground truth)")
        
        # False positives (false alarms - acceptable)
        fp_high = sum((y_test != 2) & (y_pred == 2))
        
        print(f"False Negatives (Missed Threats): {fn_high}")
        print(f"False Positives (False Alarms): {fp_high}")
        print(f"FN Rate: {fn_high / sum(y_test == 2):.2%}")
        
        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            indices = np.argsort(importances)[::-1]
            
            print("\n=== TOP 10 MOST IMPORTANT FEATURES ===")
            for i in range(min(10, len(self.feature_names))):
                idx = indices[i]
                print(f"{i+1}. {self.feature_names[idx]}: {importances[idx]:.4f}")
        
        return {
            'y_pred': y_pred,
            'y_proba': y_proba,
            'confusion_matrix': cm,
            'precision': precision,
            'recall': recall,
            'f1': f1
        }
    
    def plot_confusion_matrix(self, cm):
        """Visualize confusion matrix"""
        
        plt.figure(figsize=(10, 8))
        sns.heatmap(
            cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Low', 'Medium', 'High'],
            yticklabels=['Low', 'Medium', 'High']
        )
        plt.title('Confusion Matrix - IAM Risk Prediction')
        plt.ylabel('True Risk Level')
        plt.xlabel('Predicted Risk Level')
        plt.tight_layout()
        plt.savefig('output/confusion_matrix.png', dpi=300)
        plt.close()
    
    def plot_feature_importance(self):
        """Visualize feature importance"""
        
        if not hasattr(self.model, 'feature_importances_'):
            print("Model doesn't have feature importance")
            return
            
        importances = self.model.feature_importances_
        indices = np.argsort(importances)[::-1][:15]  # Top 15
        
        plt.figure(figsize=(12, 8))
        plt.barh(range(len(indices)), importances[indices])
        plt.yticks(range(len(indices)), [self.feature_names[i] for i in indices])
        plt.xlabel('Feature Importance')
        plt.title('Top 15 Features for IAM Risk Prediction')
        plt.tight_layout()
        plt.savefig('output/feature_importance.png', dpi=300)
        plt.close()
    
    def save_model(self, filename='models/iam_risk_model.pkl'):
        """Save trained model"""
        with open(filename, 'wb') as f:
            pickle.dump(self.model, f)
        print(f"Model saved to {filename}")

# Main training script
if __name__ == "__main__":
    import os
    os.makedirs('models', exist_ok=True)
    os.makedirs('output', exist_ok=True)
    
    # Load labeled data
    df = pd.read_csv('data/labeled_features.csv')
    print(f"Loaded {len(df)} labeled policies")

    # Remove abstain labels (-1)
    mask = df['risk_label'] != -1
    df = df[mask].reset_index(drop=True)
    print(f"After removing abstains: {len(df)} samples")

    # Initialize model
    model_trainer = IAMRiskModel()
    X, y = model_trainer.prepare_data(df)

    # Prepare data
    X, y = model_trainer.prepare_data(df)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Training set: {len(X_train)}")
    print(f"Test set: {len(X_test)}")
    
    # Train models
    print("\n" + "="*60)
    print("TRAINING MODELS")
    print("="*60)
    
    # Baseline
    print("\n1. Rule-based Baseline")
    baseline = model_trainer.train_baseline(X_train, y_train)
    y_pred_baseline = baseline(X_test)
    baseline_f1 = f1_score(y_test, y_pred_baseline, average='weighted')
    print(f"Baseline F1-Score: {baseline_f1:.4f}")
    
    # Random Forest
    print("\n2. Training Random Forest...")
    model_trainer.train_random_forest(X_train, y_train)
    results_rf = model_trainer.evaluate(X_test, y_test)
    
    # XGBoost
    print("\n3. Training XGBoost...")
    model_trainer.train_xgboost(X_train, y_train)
    results_xgb = model_trainer.evaluate(X_test, y_test)
    
    # Plot results
    model_trainer.plot_confusion_matrix(results_xgb['confusion_matrix'])
    model_trainer.plot_feature_importance()
    
    # Save best model
    model_trainer.save_model()
    
    print("\nTraining complete!")
