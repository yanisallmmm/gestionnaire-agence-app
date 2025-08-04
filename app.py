#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBER EMAIL MANAGER - VERSION PROFESSIONNELLE 2025
Architecture modulaire et interface moderne
Résolution des problèmes de licence et d'affichage des boutons
"""

import os
import sys
import json
import base64
import hashlib
import secrets
import threading
import queue
import time
import re
import csv
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Union, Tuple
from contextlib import contextmanager

# Interface graphique
import tkinter as tk
from tkinter import messagebox, ttk, filedialog, simpledialog
from tkinter import font as tkFont

# Dépendances optionnelles avec gestion d'erreurs améliorée
try:
    import customtkinter as ctk
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    HAS_CUSTOMTKINTER = True
except ImportError:
    HAS_CUSTOMTKINTER = False

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from email.utils import parsedate_to_datetime
    HAS_GMAIL = True
except ImportError:
    HAS_GMAIL = False

# ============================================================================
# CONFIGURATION ET CONSTANTES
# ============================================================================

@dataclass
class AppConfig:
    """Configuration centralisée de l'application"""
    APP_NAME = "Cyber Email Manager"
    VERSION = "2025.1.0"
    APP_DIR = Path.home() / ".cyber_email_manager"
    DATA_DIR = APP_DIR / "data"
    LICENSES_DIR = APP_DIR / "licenses"
    TOKENS_DIR = APP_DIR / "tokens"
    LOGS_DIR = APP_DIR / "logs"
    
    # Clés de sécurité
    MASTER_KEY = "CYBER-ADMIN-2025-ULTRA-SECRET"
    SALT = b"cyber_email_manager_salt_2025"
    
    # Limites
    MAX_ACCOUNTS_DEFAULT = 50
    MAX_EMAILS_DEFAULT = 100
    
    @classmethod
    def init_directories(cls):
        """Initialise tous les répertoires nécessaires"""
        for directory in [cls.APP_DIR, cls.DATA_DIR, cls.LICENSES_DIR, 
                         cls.TOKENS_DIR, cls.LOGS_DIR]:
            directory.mkdir(parents=True, exist_ok=True)

@dataclass
class CyberTheme:
    """Thème cyberpunk professionnel"""
    # Couleurs principales
    bg_primary = "#0a0a0a"
    bg_secondary = "#1a1a2e"
    bg_accent = "#16213e"
    
    # Couleurs d'accent
    neon_pink = "#ff0080"
    neon_cyan = "#00ff9f"
    neon_blue = "#0080ff"
    neon_purple = "#8000ff"
    
    # Couleurs de statut
    success = "#00ff9f"
    warning = "#ffaa00"
    error = "#ff3366"
    info = "#0080ff"
    
    # Texte
    text_primary = "#ffffff"
    text_secondary = "#b0b0b0"
    text_accent = "#ff0080"
    
    # Bordures
    border_color = "#333366"
    border_active = "#ff0080"

# ============================================================================
# GESTION DES LICENCES SIMPLIFIÉE
# ============================================================================

class LicenseManager:
    """Gestionnaire de licences simplifié et fiable"""
    
    def __init__(self):
        self.licenses_file = AppConfig.LICENSES_DIR / "licenses.json"
        self.licenses = self._load_licenses()
        self._init_default_licenses()
    
    def _load_licenses(self) -> Dict:
        """Charge les licences depuis le fichier"""
        try:
            if self.licenses_file.exists():
                with open(self.licenses_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Erreur de chargement des licences: {e}")
        return {}
    
    def _save_licenses(self):
        """Sauvegarde les licences"""
        try:
            with open(self.licenses_file, 'w', encoding='utf-8') as f:
                json.dump(self.licenses, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Erreur de sauvegarde des licences: {e}")
    
    def _init_default_licenses(self):
        """Initialise les licences par défaut"""
        # Licence administrateur
        admin_key = AppConfig.MASTER_KEY
        if admin_key not in self.licenses:
            self.licenses[admin_key] = {
                'type': 'admin',
                'agency_name': 'ADMINISTRATEUR',
                'created_date': datetime.now().isoformat(),
                'max_accounts': 999,
                'status': 'active',
                'expires_date': None
            }
        
        # Licence de démonstration
        demo_key = "DEMO-2025"
        if demo_key not in self.licenses:
            self.licenses[demo_key] = {
                'type': 'demo',
                'agency_name': 'DEMONSTRATION',
                'created_date': datetime.now().isoformat(),
                'max_accounts': 5,
                'status': 'active',
                'expires_date': (datetime.now() + timedelta(days=30)).isoformat()
            }
        
        self._save_licenses()
    
    def validate_license(self, license_key: str) -> Dict:
        """Valide une licence et retourne ses informations"""
        if not license_key or not license_key.strip():
            return {'valid': False, 'error': 'Clé de licence vide'}
        
        license_key = license_key.strip().upper()
        
        if license_key not in self.licenses:
            return {'valid': False, 'error': 'Licence inconnue'}
        
        license_data = self.licenses[license_key]
        
        # Vérification du statut
        if license_data.get('status') != 'active':
            return {'valid': False, 'error': 'Licence désactivée'}
        
        # Vérification de l'expiration
        expires_date = license_data.get('expires_date')
        if expires_date:
            try:
                if datetime.now() > datetime.fromisoformat(expires_date):
                    return {'valid': False, 'error': 'Licence expirée'}
            except ValueError:
                pass
        
        # Mise à jour de l'usage
        license_data['last_used'] = datetime.now().isoformat()
        license_data['usage_count'] = license_data.get('usage_count', 0) + 1
        self._save_licenses()
        
        return {
            'valid': True,
            'type': license_data.get('type', 'user'),
            'agency_name': license_data.get('agency_name', 'Agence'),
            'max_accounts': license_data.get('max_accounts', AppConfig.MAX_ACCOUNTS_DEFAULT),
            'expires_date': expires_date
        }
    
    def create_license(self, agency_name: str, duration_days: Optional[int] = None, 
                      max_accounts: int = 50) -> str:
        """Crée une nouvelle licence"""
        license_key = f"CYBER-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
        
        license_data = {
            'type': 'user',
            'agency_name': agency_name,
            'created_date': datetime.now().isoformat(),
            'max_accounts': max_accounts,
            'status': 'active',
            'usage_count': 0
        }
        
        if duration_days:
            license_data['expires_date'] = (datetime.now() + timedelta(days=duration_days)).isoformat()
        else:
            license_data['expires_date'] = None
        
        self.licenses[license_key] = license_data
        self._save_licenses()
        
        return license_key
    
    def get_all_licenses(self) -> Dict:
        """Retourne toutes les licences"""
        return self.licenses.copy()
    
    def revoke_license(self, license_key: str):
        """Révoque une licence"""
        if license_key in self.licenses:
            self.licenses[license_key]['status'] = 'revoked'
            self._save_licenses()

# ============================================================================
# ANALYSEUR D'EMAILS INTELLIGENT
# ============================================================================

class EmailAnalyzer:
    """Analyseur d'emails avec reconnaissance de motifs avancée"""
    
    def __init__(self):
        self.patterns = {
            'rdv_attribue': {
                'patterns': [
                    r'rendez[- ]vous\s+a\s+été\s+attribué',
                    r'appointment\s+has\s+been\s+assigned',
                    r'rdv\s+confirmé',
                    r'votre\s+demande\s+a\s+été\s+traitée',
                    r'date\s+et\s+heure\s*:'
                ],
                'icon': '✅',
                'status': 'RDV ATTRIBUÉ',
                'color': 'success',
                'priority': 1
            },
            'demande_expiree': {
                'patterns': [
                    r'demande\s+est\s+arrivée\s+à\s+expiration',
                    r'request\s+has\s+expired',
                    r'demande\s+expirée',
                    r'délai\s+dépassé'
                ],
                'icon': '❌',
                'status': 'DEMANDE EXPIRÉE',
                'color': 'error',
                'priority': 4
            },
            'en_attente': {
                'patterns': [
                    r'en\s+attente\s+d[\'\"]*un\s+créneau',
                    r'waiting\s+for\s+available\s+slot',
                    r'toujours\s+enregistrée',
                    r'demande\s+en\s+cours'
                ],
                'icon': '⏳',
                'status': 'EN ATTENTE',
                'color': 'warning',
                'priority': 2
            },
            'compte_cree': {
                'patterns': [
                    r'compte\s+vient\s+d[\'\"]*être\s+créé',
                    r'account\s+has\s+been\s+created',
                    r'définissez\s+votre\s+mot\s+de\s+passe',
                    r'bienvenue'
                ],
                'icon': '🆕',
                'status': 'COMPTE CRÉÉ',
                'color': 'info',
                'priority': 3
            }
        }
    
    def analyze_email(self, subject: str, body: str) -> Dict:
        """Analyse un email et retourne le statut détecté"""
        full_text = f"{subject}\n{body}".lower()
        
        # Extraction des informations
        reference = self._extract_reference(full_text)
        rdv_date = self._extract_rdv_date(full_text)
        
        # Détection du statut
        for status_key, config in self.patterns.items():
            for pattern in config['patterns']:
                if re.search(pattern, full_text, re.IGNORECASE):
                    return {
                        'status_key': status_key,
                        'icon': config['icon'],
                        'status': config['status'],
                        'color': config['color'],
                        'priority': config['priority'],
                        'reference': reference,
                        'rdv_date': rdv_date,
                        'confidence': 0.9
                    }
        
        # Statut par défaut
        return {
            'status_key': 'unknown',
            'icon': '❓',
            'status': 'STATUT INCONNU',
            'color': 'info',
            'priority': 5,
            'reference': reference,
            'rdv_date': rdv_date,
            'confidence': 0.1
        }
    
    def _extract_reference(self, text: str) -> str:
        """Extrait la référence de l'email"""
        patterns = [
            r'référence\s*[:\s]+([A-Z0-9]+)',
            r'ref\s*[:\s]+([A-Z0-9]+)',
            r'dossier\s*[:\s]+([A-Z0-9]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return 'N/A'
    
    def _extract_rdv_date(self, text: str) -> Optional[str]:
        """Extrait la date de RDV"""
        patterns = [
            r'date\s+et\s+heure\s*:\s*(\d{1,2}/\d{1,2}/\d{4}\s*\d{1,2}:\d{2})',
            r'rendez[- ]vous\s+le\s+(\d{1,2}/\d{1,2}/\d{4})',
            r'(\d{1,2}/\d{1,2}/\d{4}\s+à\s+\d{1,2}h\d{2})'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None

# ============================================================================
# GESTIONNAIRE GMAIL SIMPLIFIÉ
# ============================================================================

class GmailManager:
    """Gestionnaire Gmail simplifié et robuste"""
    
    SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
    
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.token_file = AppConfig.TOKENS_DIR / f"gmail_token_{user_id}.json"
        self.credentials = None
        self.service = None
    
    def authenticate(self, credentials_file: str = "credentials.json") -> bool:
        """Authentification Gmail simplifiée"""
        if not HAS_GMAIL:
            print("Les bibliothèques Gmail ne sont pas installées")
            return False
        
        try:
            # Chargement des tokens existants
            if self.token_file.exists():
                self.credentials = Credentials.from_authorized_user_file(
                    str(self.token_file), self.SCOPES
                )
            
            # Renouvellement ou nouvelle authentification
            if not self.credentials or not self.credentials.valid:
                if (self.credentials and self.credentials.expired and 
                    self.credentials.refresh_token):
                    self.credentials.refresh(Request())
                else:
                    if not os.path.exists(credentials_file):
                        print(f"Fichier {credentials_file} manquant")
                        return False
                    
                    flow = InstalledAppFlow.from_client_secrets_file(
                        credentials_file, self.SCOPES
                    )
                    self.credentials = flow.run_local_server(port=0)
                
                # Sauvegarde des tokens
                with open(self.token_file, 'w') as token:
                    token.write(self.credentials.to_json())
            
            # Création du service
            self.service = build('gmail', 'v1', credentials=self.credentials)
            return True
            
        except Exception as e:
            print(f"Erreur d'authentification Gmail: {e}")
            return False
    
    def get_user_email(self) -> Optional[str]:
        """Récupère l'adresse email de l'utilisateur"""
        try:
            if self.service:
                profile = self.service.users().getProfile(userId='me').execute()
                return profile.get('emailAddress')
        except Exception as e:
            print(f"Erreur récupération email: {e}")
        return None
    
    def search_emails(self, sender_email: str, max_results: int = 10) -> List[Dict]:
        """Recherche des emails d'un expéditeur"""
        try:
            if not self.service:
                return []
            
            # Recherche des messages
            query = f'from:{sender_email}'
            results = self.service.users().messages().list(
                userId='me', q=query, maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            emails = []
            
            for message in messages:
                try:
                    # Récupération des détails
                    msg = self.service.users().messages().get(
                        userId='me', id=message['id']
                    ).execute()
                    
                    # Extraction des headers
                    headers = {h['name'].lower(): h['value'] 
                             for h in msg['payload']['headers']}
                    
                    # Extraction du corps
                    body = self._extract_body(msg['payload'])
                    
                    # Formatage de la date
                    date_str = headers.get('date', '')
                    formatted_date = self._format_date(date_str)
                    
                    emails.append({
                        'id': message['id'],
                        'subject': headers.get('subject', 'Sans sujet'),
                        'sender': headers.get('from', 'Expéditeur inconnu'),
                        'date': formatted_date,
                        'body': body,
                        'raw_date': date_str
                    })
                    
                except Exception as e:
                    print(f"Erreur traitement message {message['id']}: {e}")
                    continue
            
            return emails
            
        except Exception as e:
            print(f"Erreur recherche emails: {e}")
            return []
    
    def _extract_body(self, payload) -> str:
        """Extrait le corps du message"""
        body = ""
        
        try:
            if 'parts' in payload:
                for part in payload['parts']:
                    if part['mimeType'] == 'text/plain':
                        data = part['body'].get('data')
                        if data:
                            body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                            break
            elif payload['body'].get('data'):
                body = base64.urlsafe_b64decode(
                    payload['body']['data']
                ).decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"Erreur extraction corps: {e}")
        
        return body
    
    def _format_date(self, date_str: str) -> str:
        """Formate la date de l'email"""
        try:
            parsed_date = parsedate_to_datetime(date_str)
            return parsed_date.strftime('%d/%m/%Y %H:%M')
        except Exception:
            return date_str

# ============================================================================
# INTERFACE UTILISATEUR MODERNE
# ============================================================================

class ModernUI:
    """Interface utilisateur moderne et robuste"""
    
    def __init__(self, theme: CyberTheme = None):
        self.theme = theme or CyberTheme()
        self.fonts = self._init_fonts()
    
    def _init_fonts(self) -> Dict:
        """Initialise les polices"""
        try:
            return {
                'title': ('Arial', 24, 'bold'),
                'subtitle': ('Arial', 16, 'bold'),
                'normal': ('Arial', 10),
                'small': ('Arial', 8),
                'code': ('Courier New', 10),
                'button': ('Arial', 10, 'bold')
            }
        except Exception:
            # Polices par défaut si problème
            return {
                'title': ('TkDefaultFont', 24, 'bold'),
                'subtitle': ('TkDefaultFont', 16, 'bold'),
                'normal': ('TkDefaultFont', 10),
                'small': ('TkDefaultFont', 8),
                'code': ('TkFixedFont', 10),
                'button': ('TkDefaultFont', 10, 'bold')
            }
    
    def create_frame(self, parent, **kwargs):
        """Crée un frame avec le style du thème"""
        frame = tk.Frame(
            parent,
            bg=self.theme.bg_secondary,
            relief='flat',
            bd=1,
            **kwargs
        )
        return frame
    
    def create_button(self, parent, text, command=None, style='normal', **kwargs):
        """Crée un bouton stylisé"""
        colors = {
            'normal': (self.theme.neon_blue, self.theme.text_primary),
            'success': (self.theme.success, self.theme.bg_primary),
            'warning': (self.theme.warning, self.theme.bg_primary),
            'error': (self.theme.error, self.theme.text_primary),
            'info': (self.theme.info, self.theme.text_primary)
        }
        
        bg_color, fg_color = colors.get(style, colors['normal'])
        
        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=bg_color,
            fg=fg_color,
            font=self.fonts['button'],
            relief='flat',
            bd=0,
            padx=20,
            pady=10,
            cursor='hand2',
            **kwargs
        )
        
        # Effets de survol
        def on_enter(e):
            button.configure(bg=self._lighten_color(bg_color))
        
        def on_leave(e):
            button.configure(bg=bg_color)
        
        button.bind('<Enter>', on_enter)
        button.bind('<Leave>', on_leave)
        
        return button
    
    def create_entry(self, parent, placeholder='', **kwargs):
        """Crée un champ de saisie stylisé"""
        entry = tk.Entry(
            parent,
            bg=self.theme.bg_accent,
            fg=self.theme.text_primary,
            font=self.fonts['normal'],
            relief='flat',
            bd=2,
            insertbackground=self.theme.text_primary,
            **kwargs
        )
        
        # Placeholder
        if placeholder:
            entry.insert(0, placeholder)
            entry.configure(fg=self.theme.text_secondary)
            
            def on_focus_in(event):
                if entry.get() == placeholder:
                    entry.delete(0, tk.END)
                    entry.configure(fg=self.theme.text_primary)
            
            def on_focus_out(event):
                if not entry.get():
                    entry.insert(0, placeholder)
                    entry.configure(fg=self.theme.text_secondary)
            
            entry.bind('<FocusIn>', on_focus_in)
            entry.bind('<FocusOut>', on_focus_out)
        
        return entry
    
    def create_text(self, parent, **kwargs):
        """Crée une zone de texte stylisée"""
        text_widget = tk.Text(
            parent,
            bg=self.theme.bg_primary,
            fg=self.theme.text_primary,
            font=self.fonts['code'],
            relief='flat',
            bd=2,
            insertbackground=self.theme.text_primary,
            wrap=tk.WORD,
            **kwargs
        )
        
        # Configuration des tags pour coloration
        text_widget.tag_configure('success', foreground=self.theme.success)
        text_widget.tag_configure('error', foreground=self.theme.error)
        text_widget.tag_configure('warning', foreground=self.theme.warning)
        text_widget.tag_configure('info', foreground=self.theme.info)
        text_widget.tag_configure('accent', foreground=self.theme.neon_pink)
        text_widget.tag_configure('header', 
                                foreground=self.theme.neon_cyan, 
                                font=self.fonts['subtitle'])
        
        return text_widget
    
    def create_listbox(self, parent, **kwargs):
        """Crée une listbox stylisée"""
        listbox = tk.Listbox(
            parent,
            bg=self.theme.bg_accent,
            fg=self.theme.text_primary,
            font=self.fonts['normal'],
            relief='flat',
            bd=2,
            selectbackground=self.theme.neon_pink,
            selectforeground=self.theme.bg_primary,
            **kwargs
        )
        
        return listbox
    
    def _lighten_color(self, color: str) -> str:
        """Éclaircit une couleur (simulation simple)"""
        # Simulation simple d'éclaircissement
        if color == self.theme.neon_blue:
            return "#4da6ff"
        elif color == self.theme.success:
            return "#4dffb3"
        elif color == self.theme.warning:
            return "#ffcc4d"
        elif color == self.theme.error:
            return "#ff6699"
        else:
            return color
    
    def show_notification(self, parent, message, style='info', duration=3000):
        """Affiche une notification"""
        colors = {
            'info': self.theme.info,
            'success': self.theme.success,
            'warning': self.theme.warning,
            'error': self.theme.error
        }
        
        color = colors.get(style, colors['info'])
        
        notification = tk.Toplevel(parent)
        notification.overrideredirect(True)
        notification.configure(bg=color)
        
        # Positionnement
        x = parent.winfo_x() + 50
        y = parent.winfo_y() + 50
        notification.geometry(f"400x80+{x}+{y}")
        
        # Contenu
        label = tk.Label(
            notification,
            text=message,
            bg=color,
            fg=self.theme.text_primary,
            font=self.fonts['normal'],
            wraplength=350
        )
        label.pack(expand=True, fill='both', padx=10, pady=10)
        
        # Auto-destruction
        notification.after(duration, notification.destroy)

# ============================================================================
# FENÊTRE DE CONNEXION AMÉLIORÉE
# ============================================================================

class LoginWindow:
    """Fenêtre de connexion moderne et robuste"""
    
    def __init__(self, callback):
        self.callback = callback
        self.license_manager = LicenseManager()
        self.ui = ModernUI()
        
        self.root = tk.Tk()
        self._setup_window()
        self._create_widgets()
    
    def _setup_window(self):
        """Configuration de la fenêtre"""
        self.root.title(f"{AppConfig.APP_NAME} - Connexion")
        self.root.geometry("500x400")
        self.root.configure(bg=self.ui.theme.bg_primary)
        self.root.resizable(False, False)
        
        # Centrage
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.root.winfo_screenheight() // 2) - (400 // 2)
        self.root.geometry(f"500x400+{x}+{y}")
    
    def _create_widgets(self):
        """Création des widgets"""
        # Frame principal
        main_frame = self.ui.create_frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Titre
        title_label = tk.Label(
            main_frame,
            text=AppConfig.APP_NAME.upper(),
            font=self.ui.fonts['title'],
            fg=self.ui.theme.neon_pink,
            bg=self.ui.theme.bg_secondary
        )
        title_label.pack(pady=(30, 10))
        
        # Version
        version_label = tk.Label(
            main_frame,
            text=f"Version {AppConfig.VERSION}",
            font=self.ui.fonts['small'],
            fg=self.ui.theme.text_secondary,
            bg=self.ui.theme.bg_secondary
        )
        version_label.pack(pady=(0, 30))
        
        # Instructions
        instruction_label = tk.Label(
            main_frame,
            text="Entrez votre clé de licence pour continuer",
            font=self.ui.fonts['normal'],
            fg=self.ui.theme.text_primary,
            bg=self.ui.theme.bg_secondary
        )
        instruction_label.pack(pady=(0, 20))
        
        # Champ de saisie
        self.license_entry = self.ui.create_entry(
            main_frame,
            placeholder="Clé de licence...",
            width=40
        )
        self.license_entry.pack(pady=10, ipady=8)
        self.license_entry.focus()
        
        # Bouton de validation
        self.validate_button = self.ui.create_button(
            main_frame,
            text="🚀 VALIDER",
            command=self._validate_license,
            style='success',
            width=20
        )
        self.validate_button.pack(pady=20)
        
        # Message de statut
        self.status_label = tk.Label(
            main_frame,
            text="",
            font=self.ui.fonts['small'],
            fg=self.ui.theme.text_secondary,
            bg=self.ui.theme.bg_secondary
        )
        self.status_label.pack(pady=10)
        
        # Exemples de licences
        examples_frame = self.ui.create_frame(main_frame)
        examples_frame.pack(pady=20, fill='x')
        
        tk.Label(
            examples_frame,
            text="Licences de test disponibles:",
            font=self.ui.fonts['small'],
            fg=self.ui.theme.text_secondary,
            bg=self.ui.theme.bg_secondary
        ).pack()
        
        tk.Label(
            examples_frame,
            text="DEMO-2025 (Démonstration) | CYBER-ADMIN-2025-ULTRA-SECRET (Admin)",
            font=self.ui.fonts['small'],
            fg=self.ui.theme.neon_cyan,
            bg=self.ui.theme.bg_secondary
        ).pack()
        
        # Binding Enter
        self.root.bind('<Return>', lambda e: self._validate_license())
    
    def _validate_license(self):
        """Validation de la licence"""
        license_key = self.license_entry.get().strip()
        
        # Nettoyage du placeholder
        if license_key == "Clé de licence...":
            license_key = ""
        
        if not license_key:
            self._show_status("⚠️ Veuillez entrer une clé de licence", "warning")
            return
        
        self._show_status("🔄 Validation en cours...", "info")
        self.validate_button.configure(state='disabled')
        
        # Validation dans un thread pour éviter le blocage de l'UI
        def validate():
            try:
                result = self.license_manager.validate_license(license_key)
                
                # Mise à jour de l'UI dans le thread principal
                self.root.after(0, lambda: self._handle_validation_result(license_key, result))
                
            except Exception as e:
                self.root.after(0, lambda: self._show_status(f"❌ Erreur: {e}", "error"))
                self.root.after(0, lambda: self.validate_button.configure(state='normal'))
        
        threading.Thread(target=validate, daemon=True).start()
    
    def _handle_validation_result(self, license_key, result):
        """Gère le résultat de la validation"""
        if result['valid']:
            self._show_status("✅ Licence valide! Connexion...", "success")
            self.root.after(1500, lambda: self._connect(license_key, result))
        else:
            error_msg = result.get('error', 'Licence invalide')
            self._show_status(f"❌ {error_msg}", "error")
            self.validate_button.configure(state='normal')
    
    def _connect(self, license_key, license_info):
        """Effectue la connexion"""
        self.root.destroy()
        self.callback(license_key, license_info)
    
    def _show_status(self, message, style='info'):
        """Affiche un message de statut"""
        colors = {
            'info': self.ui.theme.info,
            'success': self.ui.theme.success,
            'warning': self.ui.theme.warning,
            'error': self.ui.theme.error
        }
        
        color = colors.get(style, colors['info'])
        self.status_label.configure(text=message, fg=color)
    
    def show(self):
        """Affiche la fenêtre"""
        self.root.mainloop()

# ============================================================================
# FENÊTRE UTILISATEUR PRINCIPALE
# ============================================================================

class UserWindow:
    """Fenêtre utilisateur principale avec interface moderne"""
    
    def __init__(self, license_key, license_info):
        self.license_key = license_key
        self.license_info = license_info
        self.ui = ModernUI()
        self.email_analyzer = EmailAnalyzer()
        
        # Données
        self.gmail_accounts = []
        self.analysis_results = []
        self.is_analyzing = False
        
        # Queue pour les mises à jour UI
        self.ui_queue = queue.Queue()
        
        self.root = tk.Tk()
        self._setup_window()
        self._create_widgets()
        self._load_user_data()
        self._start_ui_updater()
    
    def _setup_window(self):
        """Configuration de la fenêtre"""
        agency_name = self.license_info.get('agency_name', 'Utilisateur')
        self.root.title(f"{AppConfig.APP_NAME} - {agency_name}")
        self.root.geometry("1400x900")
        self.root.configure(bg=self.ui.theme.bg_primary)
        self.root.state('zoomed')  # Maximiser sur Windows
    
    def _create_widgets(self):
        """Création de l'interface utilisateur"""
        # Header
        self._create_header()
        
        # Frame principal
        main_frame = self.ui.create_frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Création des panneaux
        self._create_accounts_panel(main_frame)
        self._create_controls_panel(main_frame)
        self._create_results_panel(main_frame)
    
    def _create_header(self):
        """Crée l'en-tête de l'application"""
        header_frame = self.ui.create_frame(self.root)
        header_frame.pack(fill='x', padx=10, pady=5)
        
        # Titre
        title_label = tk.Label(
            header_frame,
            text=AppConfig.APP_NAME,
            font=self.ui.fonts['title'],
            fg=self.ui.theme.neon_pink,
            bg=self.ui.theme.bg_secondary
        )
        title_label.pack(side='left', padx=20, pady=10)
        
        # Informations utilisateur
        agency = self.license_info.get('agency_name', 'N/A')
        expires = self.license_info.get('expires_date')
        if expires:
            expires = expires.split('T')[0]
        else:
            expires = 'Illimitée'
        
        info_text = f"Agence: {agency} | Expire: {expires} | Max comptes: {self.license_info.get('max_accounts', 'N/A')}"
        
        info_label = tk.Label(
            header_frame,
            text=info_text,
            font=self.ui.fonts['normal'],
            fg=self.ui.theme.text_secondary,
            bg=self.ui.theme.bg_secondary
        )
        info_label.pack(side='right', padx=20, pady=10)
    
    def _create_accounts_panel(self, parent):
        """Crée le panneau de gestion des comptes"""
        # Frame des comptes
        accounts_frame = tk.LabelFrame(
            parent,
            text="COMPTES GMAIL",
            font=self.ui.fonts['subtitle'],
            fg=self.ui.theme.neon_cyan,
            bg=self.ui.theme.bg_secondary,
            bd=2
        )
        accounts_frame.pack(side='left', fill='y', padx=5, pady=5)
        
        # Liste des comptes
        self.accounts_listbox = self.ui.create_listbox(
            accounts_frame,
            width=35,
            height=25
        )
        self.accounts_listbox.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Boutons de gestion
        buttons_frame = self.ui.create_frame(accounts_frame)
        buttons_frame.pack(fill='x', padx=10, pady=5)
        
        self.ui.create_button(
            buttons_frame,
            text="➕ Ajouter Compte",
            command=self._add_gmail_account,
            style='success'
        ).pack(fill='x', pady=2)
        
        self.ui.create_button(
            buttons_frame,
            text="🗑️ Supprimer",
            command=self._remove_gmail_account,
            style='error'
        ).pack(fill='x', pady=2)
        
        # Statistiques
        self.accounts_stats = tk.Label(
            accounts_frame,
            text="0 compte",
            font=self.ui.fonts['small'],
            fg=self.ui.theme.text_secondary,
            bg=self.ui.theme.bg_secondary
        )
        self.accounts_stats.pack(pady=5)
    
    def _create_controls_panel(self, parent):
        """Crée le panneau de contrôles"""
        controls_frame = tk.LabelFrame(
            parent,
            text="CONTRÔLES D'ANALYSE",
            font=self.ui.fonts['subtitle'],
            fg=self.ui.theme.neon_cyan,
            bg=self.ui.theme.bg_secondary,
            bd=2
        )
        controls_frame.pack(side='left', fill='y', padx=5, pady=5)
        
        # Configuration
        config_frame = self.ui.create_frame(controls_frame)
        config_frame.pack(fill='x', padx=10, pady=10)
        
        tk.Label(
            config_frame,
            text="Expéditeur à rechercher:",
            font=self.ui.fonts['normal'],
            fg=self.ui.theme.text_primary,
            bg=self.ui.theme.bg_secondary
        ).pack(anchor='w')
        
        self.sender_entry = self.ui.create_entry(
            config_frame,
            placeholder="infofrance-dz@capago.eu",
            width=35
        )
        self.sender_entry.pack(pady=5, fill='x')
        
        tk.Label(
            config_frame,
            text="Nombre d'emails max:",
            font=self.ui.fonts['normal'],
            fg=self.ui.theme.text_primary,
            bg=self.ui.theme.bg_secondary
        ).pack(anchor='w', pady=(10, 0))
        
        self.max_emails_entry = self.ui.create_entry(
            config_frame,
            placeholder="20",
            width=35
        )
        self.max_emails_entry.pack(pady=5, fill='x')
        
        # Boutons d'analyse
        analysis_frame = self.ui.create_frame(controls_frame)
        analysis_frame.pack(fill='x', padx=10, pady=20)
        
        self.analyze_selected_btn = self.ui.create_button(
            analysis_frame,
            text="🔍 Analyser Sélectionné",
            command=self._analyze_selected,
            style='normal'
        )
        self.analyze_selected_btn.pack(fill='x', pady=2)
        
        self.analyze_all_btn = self.ui.create_button(
            analysis_frame,
            text="🔍 Analyser Tous",
            command=self._analyze_all,
            style='success'
        )
        self.analyze_all_btn.pack(fill='x', pady=2)
        
        self.stop_btn = self.ui.create_button(
            analysis_frame,
            text="⏹️ Arrêter",
            command=self._stop_analysis,
            style='error'
        )
        self.stop_btn.pack(fill='x', pady=2)
        
        # Barre de progression
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            controls_frame,
            variable=self.progress_var,
            maximum=100
        )
        self.progress_bar.pack(fill='x', padx=10, pady=10)
        
        # Statut
        self.status_label = tk.Label(
            controls_frame,
            text="Prêt",
            font=self.ui.fonts['normal'],
            fg=self.ui.theme.text_primary,
            bg=self.ui.theme.bg_secondary
        )
        self.status_label.pack(pady=10)
    
    def _create_results_panel(self, parent):
        """Crée le panneau des résultats"""
        results_frame = tk.LabelFrame(
            parent,
            text="RÉSULTATS D'ANALYSE",
            font=self.ui.fonts['subtitle'],
            fg=self.ui.theme.neon_cyan,
            bg=self.ui.theme.bg_secondary,
            bd=2
        )
        results_frame.pack(side='right', fill='both', expand=True, padx=5, pady=5)
        
        # Zone de texte des résultats
        self.results_text = self.ui.create_text(
            results_frame,
            height=30,
            width=70
        )
        self.results_text.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(self.results_text)
        scrollbar.pack(side='right', fill='y')
        self.results_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.results_text.yview)
        
        # Boutons d'action
        actions_frame = self.ui.create_frame(results_frame)
        actions_frame.pack(fill='x', padx=10, pady=5)
        
        self.ui.create_button(
            actions_frame,
            text="📋 Copier",
            command=self._copy_results,
            style='normal'
        ).pack(side='left', padx=5)
        
        self.ui.create_button(
            actions_frame,
            text="💾 Exporter CSV",
            command=self._export_csv,
            style='normal'
        ).pack(side='left', padx=5)
        
        self.ui.create_button(
            actions_frame,
            text="🗑️ Effacer",
            command=self._clear_results,
            style='error'
        ).pack(side='left', padx=5)
    
    def _start_ui_updater(self):
        """Démarre le gestionnaire de mise à jour de l'UI"""
        def update_ui():
            try:
                while not self.ui_queue.empty():
                    msg_type, data = self.ui_queue.get_nowait()
                    
                    if msg_type == "status":
                        self.status_label.configure(text=data)
                    elif msg_type == "progress":
                        self.progress_var.set(data)
                    elif msg_type == "result":
                        self._display_result(data)
                    elif msg_type == "clear":
                        self.results_text.delete('1.0', tk.END)
                        self.analysis_results.clear()
                        
            except queue.Empty:
                pass
            
            self.root.after(100, update_ui)
        
        update_ui()
    
    def _load_user_data(self):
        """Charge les données utilisateur"""
        user_file = AppConfig.DATA_DIR / f"user_{hashlib.md5(self.license_key.encode()).hexdigest()}.json"
        
        try:
            if user_file.exists():
                with open(user_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.gmail_accounts = data.get('gmail_accounts', [])
        except Exception as e:
            print(f"Erreur chargement données: {e}")
            self.gmail_accounts = []
        
        self._update_accounts_display()
    
    def _save_user_data(self):
        """Sauvegarde les données utilisateur"""
        user_file = AppConfig.DATA_DIR / f"user_{hashlib.md5(self.license_key.encode()).hexdigest()}.json"
        
        try:
            data = {
                'gmail_accounts': self.gmail_accounts,
                'last_updated': datetime.now().isoformat()
            }
            
            with open(user_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            print(f"Erreur sauvegarde: {e}")
    
    def _update_accounts_display(self):
        """Met à jour l'affichage des comptes"""
        self.accounts_listbox.delete(0, tk.END)
        
        if not self.gmail_accounts:
            self.accounts_listbox.insert(tk.END, "Aucun compte ajouté")
            self.accounts_stats.configure(text="0 compte")
        else:
            for i, account in enumerate(self.gmail_accounts):
                status_icon = "✅" if account.get('status') == 'active' else "⚠️"
                text = f"{i+1}. {account['email']} {status_icon}"
                self.accounts_listbox.insert(tk.END, text)
            
            self.accounts_stats.configure(text=f"{len(self.gmail_accounts)} compte(s)")
    
    def _add_gmail_account(self):
        """Ajoute un nouveau compte Gmail"""
        if not HAS_GMAIL:
            messagebox.showerror(
                "Dépendances manquantes",
                "Les bibliothèques Gmail ne sont pas installées.\n"
                "Installez-les avec: pip install google-auth google-auth-oauthlib google-api-python-client"
            )
            return
        
        max_accounts = self.license_info.get('max_accounts', AppConfig.MAX_ACCOUNTS_DEFAULT)
        if len(self.gmail_accounts) >= max_accounts:
            messagebox.showwarning(
                "Limite atteinte",
                f"Vous avez atteint la limite de {max_accounts} comptes."
            )
            return
        
        def authenticate():
            try:
                self.ui_queue.put(("status", "Authentification Gmail..."))
                
                user_id = f"{hashlib.md5(self.license_key.encode()).hexdigest()}_{len(self.gmail_accounts)}"
                gmail_manager = GmailManager(user_id)
                
                if gmail_manager.authenticate():
                    email = gmail_manager.get_user_email()
                    if email:
                        # Vérifier les doublons
                        if any(acc['email'] == email for acc in self.gmail_accounts):
                            self.ui_queue.put(("status", f"Compte {email} déjà existant"))
                            return
                        
                        # Ajouter le compte
                        self.gmail_accounts.append({
                            'email': email,
                            'user_id': user_id,
                            'added_date': datetime.now().isoformat(),
                            'status': 'active'
                        })
                        
                        self._save_user_data()
                        self.root.after(0, self._update_accounts_display)
                        self.ui_queue.put(("status", f"Compte {email} ajouté avec succès"))
                    else:
                        self.ui_queue.put(("status", "Impossible de récupérer l'email"))
                else:
                    self.ui_queue.put(("status", "Échec de l'authentification"))
                    
            except Exception as e:
                self.ui_queue.put(("status", f"Erreur: {e}"))
        
        threading.Thread(target=authenticate, daemon=True).start()
    
    def _remove_gmail_account(self):
        """Supprime un compte Gmail"""
        selection = self.accounts_listbox.curselection()
        if not selection:
            messagebox.showwarning("Sélection", "Sélectionnez un compte à supprimer")
            return
        
        if self.accounts_listbox.get(selection[0]) == "Aucun compte ajouté":
            return
        
        account_index = selection[0]
        account = self.gmail_accounts[account_index]
        
        if messagebox.askyesno(
            "Confirmation",
            f"Supprimer le compte {account['email']} ?"
        ):
            # Supprimer le token
            token_file = AppConfig.TOKENS_DIR / f"gmail_token_{account['user_id']}.json"
            if token_file.exists():
                token_file.unlink()
            
            # Supprimer de la liste
            self.gmail_accounts.pop(account_index)
            self._save_user_data()
            self._update_accounts_display()
            
            self.ui.show_notification(
                self.root,
                f"Compte {account['email']} supprimé",
                "success"
            )
    
    def _analyze_selected(self):
        """Analyse le compte sélectionné"""
        selection = self.accounts_listbox.curselection()
        if not selection:
            messagebox.showwarning("Sélection", "Sélectionnez un compte à analyser")
            return
        
        if self.accounts_listbox.get(selection[0]) == "Aucun compte ajouté":
            return
        
        account = self.gmail_accounts[selection[0]]
        self._start_analysis([account])
    
    def _analyze_all(self):
        """Analyse tous les comptes"""
        if not self.gmail_accounts:
            messagebox.showwarning("Aucun compte", "Ajoutez des comptes Gmail d'abord")
            return
        
        self._start_analysis(self.gmail_accounts)
    
    def _start_analysis(self, accounts):
        """Démarre l'analyse des comptes"""
        if self.is_analyzing:
            messagebox.showinfo("Analyse en cours", "Une analyse est déjà en cours")
            return
        
        # Récupération des paramètres
        sender = self.sender_entry.get().strip()
        if sender == "infofrance-dz@capago.eu":
            sender = "infofrance-dz@capago.eu"  # Valeur par défaut
        elif not sender:
            messagebox.showerror("Paramètre manquant", "Spécifiez l'expéditeur à rechercher")
            return
        
        max_emails_str = self.max_emails_entry.get().strip()
        if max_emails_str == "20":
            max_emails = 20
        else:
            try:
                max_emails = int(max_emails_str) if max_emails_str else 20
            except ValueError:
                max_emails = 20
        
        self.is_analyzing = True
        self.ui_queue.put(("clear", None))
        self.ui_queue.put(("status", "Démarrage de l'analyse..."))
        self.ui_queue.put(("progress", 0))
        
        def analyze():
            try:
                total = len(accounts)
                
                for i, account in enumerate(accounts):
                    if not self.is_analyzing:  # Vérifier si l'analyse a été arrêtée
                        break
                        
                    self.ui_queue.put(("status", f"Analyse de {account['email']}..."))
                    progress = (i / total) * 100
                    self.ui_queue.put(("progress", progress))
                    
                    # Analyser le compte
                    self._analyze_account(account, sender, max_emails)
                    
                    # Pause entre les comptes
                    time.sleep(1)
                
                self.ui_queue.put(("progress", 100))
                self.ui_queue.put(("status", f"Analyse terminée - {total} compte(s)"))
                
            except Exception as e:
                self.ui_queue.put(("status", f"Erreur d'analyse: {e}"))
            finally:
                self.is_analyzing = False
        
        threading.Thread(target=analyze, daemon=True).start()
    
    def _analyze_account(self, account, sender, max_emails):
        """Analyse un compte spécifique"""
        try:
            gmail_manager = GmailManager(account['user_id'])
            
            if not gmail_manager.authenticate():
                self.ui_queue.put(("result", {
                    'type': 'error',
                    'account': account['email'],
                    'message': 'Échec de l\'authentification'
                }))
                return
            
            emails = gmail_manager.search_emails(sender, max_emails)
            
            if not emails:
                self.ui_queue.put(("result", {
                    'type': 'info',
                    'account': account['email'],
                    'message': f'Aucun email de {sender}'
                }))
                return
            
            # Analyser chaque email
            for email in emails:
                if not self.is_analyzing:
                    break
                    
                analysis = self.email_analyzer.analyze_email(
                    email['subject'], 
                    email['body']
                )
                
                self.ui_queue.put(("result", {
                    'type': 'analysis',
                    'account': account['email'],
                    'email': email,
                    'analysis': analysis
                }))
                
        except Exception as e:
            self.ui_queue.put(("result", {
                'type': 'error',
                'account': account['email'],
                'message': f'Erreur: {e}'
            }))
    
    def _stop_analysis(self):
        """Arrête l'analyse en cours"""
        self.is_analyzing = False
        self.ui_queue.put(("status", "Analyse arrêtée"))
        self.ui_queue.put(("progress", 0))
    
    def _display_result(self, result_data):
        """Affiche un résultat d'analyse"""
        result_type = result_data['type']
        account = result_data['account']
        
        if result_type == 'error':
            text = f"\n❌ ERREUR - {account}\n{result_data['message']}\n"
            self.results_text.insert(tk.END, text, 'error')
            
        elif result_type == 'info':
            text = f"\nℹ️ INFO - {account}\n{result_data['message']}\n"
            self.results_text.insert(tk.END, text, 'info')
            
        elif result_type == 'analysis':
            email = result_data['email']
            analysis = result_data['analysis']
            
            # En-tête
            header = f"\n{'='*80}\n📧 COMPTE: {account}\n{'='*80}\n"
            self.results_text.insert(tk.END, header, 'header')
            
            # Informations email
            info = f"SUJET: {email['subject']}\n"
            info += f"DATE: {email['date']}\n"
            info += f"EXPÉDITEUR: {email['sender']}\n"
            self.results_text.insert(tk.END, info, 'accent')
            
            # Résultat analyse
            status_text = f"\n{analysis['icon']} STATUT: {analysis['status']}\n"
            self.results_text.insert(tk.END, status_text, analysis['color'])
            
            if analysis['reference'] != 'N/A':
                ref_text = f"RÉFÉRENCE: {analysis['reference']}\n"
                self.results_text.insert(tk.END, ref_text, 'accent')
            
            if analysis.get('rdv_date'):
                rdv_text = f"DATE RDV: {analysis['rdv_date']}\n"
                self.results_text.insert(tk.END, rdv_text, 'success')
            
            # Aperçu du corps
            body_preview = email['body'][:300] + '...' if len(email['body']) > 300 else email['body']
            preview_text = f"\nAPERÇU:\n{body_preview}\n"
            self.results_text.insert(tk.END, preview_text)
        
        # Scroll vers le bas
        self.results_text.see(tk.END)
        
        # Sauvegarder le résultat
        self.analysis_results.append(result_data)
    
    def _copy_results(self):
        """Copie les résultats dans le presse-papiers"""
        try:
            content = self.results_text.get('1.0', tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            
            self.ui.show_notification(
                self.root,
                "Résultats copiés dans le presse-papiers",
                "success"
            )
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur de copie: {e}")
    
    def _export_csv(self):
        """Exporte les résultats en CSV"""
        if not self.analysis_results:
            messagebox.showwarning("Aucun résultat", "Aucun résultat à exporter")
            return
        
        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("Fichiers CSV", "*.csv"), ("Tous les fichiers", "*.*")],
                title="Exporter les résultats"
            )
            
            if filename:
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    
                    # En-têtes
                    writer.writerow([
                        'Compte', 'Sujet', 'Date', 'Statut', 'Référence', 
                        'Date RDV', 'Expéditeur', 'Confiance'
                    ])
                    
                    # Données
                    for result in self.analysis_results:
                        if result['type'] == 'analysis':
                            email = result['email']
                            analysis = result['analysis']
                            
                            writer.writerow([
                                result['account'],
                                email['subject'],
                                email['date'],
                                analysis['status'],
                                analysis['reference'],
                                analysis.get('rdv_date', ''),
                                email['sender'],
                                analysis.get('confidence', 0)
                            ])
                
                self.ui.show_notification(
                    self.root,
                    f"Résultats exportés: {filename}",
                    "success"
                )
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur d'exportation: {e}")
    
    def _clear_results(self):
        """Efface tous les résultats"""
        if messagebox.askyesno("Confirmation", "Effacer tous les résultats ?"):
            self.ui_queue.put(("clear", None))
            self.ui_queue.put(("status", "Résultats effacés"))
            self.ui_queue.put(("progress", 0))
    
    def show(self):
        """Affiche la fenêtre"""
        self.root.mainloop()

# ============================================================================
# FENÊTRE ADMINISTRATEUR
# ============================================================================

class AdminWindow:
    """Fenêtre d'administration des licences"""
    
    def __init__(self):
        self.license_manager = LicenseManager()
        self.ui = ModernUI()
        
        self.root = tk.Tk()
        self._setup_window()
        self._create_widgets()
        self._refresh_licenses()
    
    def _setup_window(self):
        """Configuration de la fenêtre"""
        self.root.title(f"{AppConfig.APP_NAME} - Administration")
        self.root.geometry("1000x700")
        self.root.configure(bg=self.ui.theme.bg_primary)
    
    def _create_widgets(self):
        """Création de l'interface"""
        # Header
        header_frame = self.ui.create_frame(self.root)
        header_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(
            header_frame,
            text="PANNEAU D'ADMINISTRATION",
            font=self.ui.fonts['title'],
            fg=self.ui.theme.neon_pink,
            bg=self.ui.theme.bg_secondary
        ).pack(pady=20)
        
        # Frame principal
        main_frame = self.ui.create_frame(self.root)
        main_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Liste des licences
        licenses_frame = tk.LabelFrame(
            main_frame,
            text="LICENCES",
            font=self.ui.fonts['subtitle'],
            fg=self.ui.theme.neon_cyan,
            bg=self.ui.theme.bg_secondary
        )
        licenses_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.licenses_listbox = self.ui.create_listbox(
            licenses_frame,
            height=20
        )
        self.licenses_listbox.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Boutons d'action
        buttons_frame = self.ui.create_frame(licenses_frame)
        buttons_frame.pack(fill='x', padx=10, pady=5)
        
        self.ui.create_button(
            buttons_frame,
            text="➕ Créer Licence",
            command=self._create_license,
            style='success'
        ).pack(side='left', padx=5)
        
        self.ui.create_button(
            buttons_frame,
            text="🔄 Actualiser",
            command=self._refresh_licenses,
            style='normal'
        ).pack(side='left', padx=5)
        
        self.ui.create_button(
            buttons_frame,
            text="🗑️ Révoquer",
            command=self._revoke_license,
            style='error'
        ).pack(side='left', padx=5)
        
        # Statistiques
        self.stats_label = tk.Label(
            main_frame,
            text="",
            font=self.ui.fonts['normal'],
            fg=self.ui.theme.text_primary,
            bg=self.ui.theme.bg_secondary
        )
        self.stats_label.pack(pady=10)
    
    def _refresh_licenses(self):
        """Actualise la liste des licences"""
        self.licenses_listbox.delete(0, tk.END)
        licenses = self.license_manager.get_all_licenses()
        
        active_count = 0
        total_count = len(licenses)
        
        for key, data in licenses.items():
            status = "🟢 ACTIVE" if data.get('status') == 'active' else "🔴 RÉVOQUÉE"
            if data.get('status') == 'active':
                active_count += 1
                
            agency = data.get('agency_name', 'N/A')
            license_type = data.get('type', 'user').upper()
            expires = data.get('expires_date')
            if expires :
                expires = 'Jamais'
            else:  # Sinon (si la date est None)...
                expires = 'Jamais'  # ...on utilise le mot "Jamais".
            
            usage = data.get('usage_count', 0)
            
            line = f"[{license_type}] {agency:<25} | {key:<30} | Expire: {expires:<12} | Usage: {usage:<5} | {status}"
            self.licenses_listbox.insert(tk.END, line)
            
            # Coloration selon le statut
            if data.get('status') == 'active':
                self.licenses_listbox.itemconfig(tk.END, {'fg': self.ui.theme.success})
            else:
                self.licenses_listbox.itemconfig(tk.END, {'fg': self.ui.theme.error})
        
        # Mise à jour des statistiques
        self.stats_label.configure(
            text=f"Total: {total_count} licences | Actives: {active_count} | Révoquées: {total_count - active_count}"
        )
    
    def _create_license(self):
        """Crée une nouvelle licence"""
        dialog = LicenseDialog(self.root, self.ui)
        result = dialog.show()
        
        if result:
            try:
                license_key = self.license_manager.create_license(
                    agency_name=result['agency_name'],
                    duration_days=result['duration_days'],
                    max_accounts=result['max_accounts']
                )
                
                # Copier dans le presse-papiers
                self.root.clipboard_clear()
                self.root.clipboard_append(license_key)
                
                # Notification
                self.ui.show_notification(
                    self.root,
                    f"Licence créée pour {result['agency_name']}\n"
                    f"Clé: {license_key}\n"
                    f"(Copiée dans le presse-papiers)",
                    "success"
                )
                
                self._refresh_licenses()
                
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur de création: {e}")
    
    def _revoke_license(self):
        """Révoque une licence"""
        selection = self.licenses_listbox.curselection()
        if not selection:
            messagebox.showwarning("Sélection", "Sélectionnez une licence à révoquer")
            return
        
        try:
            line = self.licenses_listbox.get(selection[0])
            # Extraire la clé de licence de la ligne
            parts = line.split(' | ')
            license_key = parts[1].strip()
            
            if messagebox.askyesno(
                "Confirmation",
                f"Révoquer la licence {license_key} ?"
            ):
                self.license_manager.revoke_license(license_key)
                self._refresh_licenses()
                
                self.ui.show_notification(
                    self.root,
                    f"Licence {license_key} révoquée",
                    "warning"
                )
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur de révocation: {e}")
    
    def show(self):
        """Affiche la fenêtre"""
        self.root.mainloop()

class LicenseDialog:
    """Dialog de création de licence"""
    
    def __init__(self, parent, ui):
        self.parent = parent
        self.ui = ui
        self.result = None
    
    def show(self):
        """Affiche le dialog"""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Créer une licence")
        self.dialog.geometry("400x350")
        self.dialog.configure(bg=self.ui.theme.bg_primary)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Centrage
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - 200
        y = (self.dialog.winfo_screenheight() // 2) - 175
        self.dialog.geometry(f"400x350+{x}+{y}")
        
        self._create_dialog_widgets()
        self.dialog.wait_window()
        return self.result
    
    def _create_dialog_widgets(self):
        """Crée les widgets du dialog"""
        main_frame = self.ui.create_frame(self.dialog)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Titre
        tk.Label(
            main_frame,
            text="CRÉER UNE LICENCE",
            font=self.ui.fonts['subtitle'],
            fg=self.ui.theme.neon_cyan,
            bg=self.ui.theme.bg_secondary
        ).pack(pady=20)
        
        # Nom de l'agence
        tk.Label(
            main_frame,
            text="Nom de l'agence:",
            font=self.ui.fonts['normal'],
            fg=self.ui.theme.text_primary,
            bg=self.ui.theme.bg_secondary
        ).pack(anchor='w', pady=(10, 5))
        
        self.agency_entry = self.ui.create_entry(
            main_frame,
            placeholder="Ex: Agence Visa Plus",
            width=35
        )
        self.agency_entry.pack(fill='x', pady=5)
        
        # Durée
        tk.Label(
            main_frame,
            text="Durée (jours, vide = illimitée):",
            font=self.ui.fonts['normal'],
            fg=self.ui.theme.text_primary,
            bg=self.ui.theme.bg_secondary
        ).pack(anchor='w', pady=(10, 5))
        
        self.duration_entry = self.ui.create_entry(
            main_frame,
            placeholder="Ex: 365",
            width=35
        )
        self.duration_entry.pack(fill='x', pady=5)
        
        # Max comptes
        tk.Label(
            main_frame,
            text="Nombre max de comptes:",
            font=self.ui.fonts['normal'],
            fg=self.ui.theme.text_primary,
            bg=self.ui.theme.bg_secondary
        ).pack(anchor='w', pady=(10, 5))
        
        self.accounts_entry = self.ui.create_entry(
            main_frame,
            placeholder="50",
            width=35
        )
        self.accounts_entry.pack(fill='x', pady=5)
        
        # Boutons
        buttons_frame = self.ui.create_frame(main_frame)
        buttons_frame.pack(pady=30)
        
        self.ui.create_button(
            buttons_frame,
            text="✅ Créer",
            command=self._create,
            style='success'
        ).pack(side='left', padx=10)
        
        self.ui.create_button(
            buttons_frame,
            text="❌ Annuler",
            command=self._cancel,
            style='error'
        ).pack(side='left', padx=10)
    
    def _create(self):
        """Crée la licence"""
        agency_name = self.agency_entry.get().strip()
        if agency_name == "Ex: Agence Visa Plus":
            agency_name = ""
            
        if not agency_name:
            messagebox.showerror("Erreur", "Le nom de l'agence est requis")
            return
        
        duration_str = self.duration_entry.get().strip()
        if duration_str == "Ex: 365":
            duration_str = ""
            
        duration_days = None
        if duration_str:
            try:
                duration_days = int(duration_str)
                if duration_days <= 0:
                    raise ValueError()
            except ValueError:
                messagebox.showerror("Erreur", "La durée doit être un nombre positif")
                return
        
        max_accounts_str = self.accounts_entry.get().strip()
        if max_accounts_str == "50":
            max_accounts = 50
        else:
            try:
                max_accounts = int(max_accounts_str) if max_accounts_str else 50
                if max_accounts <= 0:
                    raise ValueError()
            except ValueError:
                messagebox.showerror("Erreur", "Le nombre de comptes doit être positif")
                return
        
        self.result = {
            'agency_name': agency_name,
            'duration_days': duration_days,
            'max_accounts': max_accounts
        }
        self.dialog.destroy()
    
    def _cancel(self):
        """Annule la création"""
        self.dialog.destroy()

# ============================================================================
# APPLICATION PRINCIPALE
# ============================================================================

class CyberEmailManager:
    """Application principale avec gestion d'erreurs robuste"""
    
    def __init__(self):
        # Initialisation des répertoires
        AppConfig.init_directories()
        
        print(f"🚀 {AppConfig.APP_NAME} v{AppConfig.VERSION}")
        print("=" * 50)
        
        # Vérification des dépendances
        self._check_dependencies()
    
    def _check_dependencies(self):
        """Vérifie les dépendances et affiche les avertissements"""
        missing = []
        
        if not HAS_CUSTOMTKINTER:
            missing.append("customtkinter (interface améliorée)")
        
        if not HAS_PIL:
            missing.append("Pillow (support des images)")
        
        if not HAS_CRYPTO:
            missing.append("cryptography (chiffrement avancé)")
        
        if not HAS_GMAIL:
            missing.append("google-api-python-client google-auth google-auth-oauthlib (API Gmail)")
        
        if missing:
            print("⚠️  DÉPENDANCES OPTIONNELLES MANQUANTES:")
            for dep in missing:
                print(f"   - {dep}")
            print("\nL'application fonctionnera avec des fonctionnalités limitées.")
            print("=" * 50)
    
    def run(self):
        """Lance l'application"""
        try:
            def on_login_success(license_key, license_info):
                if license_info['type'] == 'admin':
                    # Fenêtre administrateur
                    admin_window = AdminWindow()
                    admin_window.show()
                else:
                    # Fenêtre utilisateur
                    user_window = UserWindow(license_key, license_info)
                    user_window.show()
            
            # Fenêtre de connexion
            login_window = LoginWindow(on_login_success)
            login_window.show()
            
        except KeyboardInterrupt:
            print("\n🛑 Arrêt de l'application par l'utilisateur")
        except Exception as e:
            print(f"❌ ERREUR FATALE: {e}")
            messagebox.showerror("Erreur fatale", f"Une erreur critique s'est produite:\n{e}")

# ============================================================================
# POINT D'ENTRÉE
# ============================================================================

def main():
    """Point d'entrée principal de l'application"""
    try:
        app = CyberEmailManager()
        app.run()
    except Exception as e:
        print(f"❌ Erreur de démarrage: {e}")
        input("Appuyez sur Entrée pour quitter...")

if __name__ == "__main__":
    main()
