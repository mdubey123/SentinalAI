# 🎨 Modern Streamlit App with Theme Toggle

A beautiful, responsive Streamlit application featuring automatic theme detection, manual theme switching, and modern UI design.

## ✨ Features

### 🎨 **Theme System**
- **Automatic Detection**: Detects your system's theme preference using `prefers-color-scheme`
- **Manual Toggle**: Switch between Light, Dark, and Auto modes
- **Persistence**: Theme preference is saved in session state
- **Smooth Transitions**: Beautiful animations when switching themes

### 🎯 **Modern Design**
- **Clean & Minimalistic**: Modern, user-friendly interface
- **Glass-morphism Effects**: Subtle backdrop blur and transparency
- **Gradient Accents**: Beautiful gradient buttons and highlights
- **Consistent Spacing**: Proper alignment and responsive design

### 📱 **Responsive Design**
- **Mobile-First**: Optimized for all screen sizes
- **Adaptive Layout**: Automatically adjusts to device capabilities
- **Touch-Friendly**: Large touch targets for mobile devices

### ♿ **Accessibility**
- **High Contrast**: Support for high contrast mode
- **Reduced Motion**: Respects user's motion preferences
- **Keyboard Navigation**: Full keyboard accessibility
- **Screen Reader**: Compatible with assistive technologies

## 🚀 Quick Start

### Installation

1. **Clone or download the files**:
   ```bash
   # Download the main app file
   # modern_streamlit_app.py
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements_modern_app.txt
   ```

3. **Run the app**:
   ```bash
   streamlit run modern_streamlit_app.py
   ```

4. **Open your browser** and navigate to `http://localhost:8501`

## 🎨 Theme System Explained

### How It Works

The theme system uses a combination of CSS variables and JavaScript to provide seamless theme switching:

1. **CSS Variables**: All colors, shadows, and design tokens are defined as CSS variables
2. **Media Queries**: `@media (prefers-color-scheme: light/dark)` detects system preference
3. **Manual Override**: CSS classes `.theme-light` and `.theme-dark` override automatic detection
4. **Session State**: Streamlit's session state persists theme choice across page reloads

### CSS Structure

```css
:root {
    /* Design tokens - consistent across themes */
    --border-radius: 12px;
    --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    
    /* Dark theme (default) */
    --bg-primary: #0f0f23;
    --text-primary: #ffffff;
}

@media (prefers-color-scheme: light) {
    :root {
        /* Light theme */
        --bg-primary: #f8fafc;
        --text-primary: #1e293b;
    }
}

/* Manual overrides */
.theme-light { /* Force light theme */ }
.theme-dark { /* Force dark theme */ }
```

## 🛠️ Code Structure

### Main Components

1. **Theme Management**:
   - `initialize_session_state()`: Sets up theme variables
   - `get_theme_css()`: Generates comprehensive CSS
   - `apply_theme()`: Applies selected theme
   - `show_toast()`: Shows theme change notifications

2. **UI Components**:
   - `create_theme_toggle()`: Theme selector in sidebar
   - `create_demo_components()`: Demo content with tabs
   - `main()`: Orchestrates the entire app

3. **CSS Features**:
   - CSS Variables for consistent theming
   - Media queries for responsive design
   - Animations and transitions
   - Accessibility features

### Key Functions

#### Theme Toggle
```python
def create_theme_toggle():
    """Create a theme toggle button in the sidebar."""
    theme_options = {
        "🌓 Auto": "auto",
        "☀️ Light": "light", 
        "🌙 Dark": "dark"
    }
    # Theme selection logic...
```

#### CSS Generation
```python
def get_theme_css() -> str:
    """Generate CSS for theme management and modern styling."""
    return """
    <style>
    /* Comprehensive CSS with variables, media queries, and animations */
    </style>
    """
```

## 🎯 Usage Examples

### Basic Theme Switching

```python
# In your Streamlit app
import streamlit as st

# Initialize theme
if 'theme' not in st.session_state:
    st.session_state.theme = 'auto'

# Apply theme
apply_theme(st.session_state.theme)

# Theme toggle in sidebar
create_theme_toggle()
```

### Custom Components

```python
# Create themed cards
st.markdown('<div class="modern-card fade-in">', unsafe_allow_html=True)
st.markdown("Your content here")
st.markdown('</div>', unsafe_allow_html=True)

# Show notifications
show_toast("Theme changed successfully!", "success")
```

## 📱 Responsive Design

The app automatically adapts to different screen sizes:

- **Desktop (>768px)**: Full layout with sidebar
- **Tablet (768px-1024px)**: Optimized spacing
- **Mobile (<768px)**: Stacked layout, larger touch targets

### CSS Media Queries

```css
@media (max-width: 768px) {
    .modern-card {
        padding: 1rem !important;
    }
    
    .stButton > button {
        padding: 0.5rem 1rem !important;
    }
}
```

## ♿ Accessibility Features

### High Contrast Support
```css
@media (prefers-contrast: high) {
    :root {
        --border-primary: rgba(255, 255, 255, 0.3) !important;
        --text-secondary: #d0d0d0 !important;
    }
}
```

### Reduced Motion
```css
@media (prefers-reduced-motion: reduce) {
    * {
        transition: none !important;
        animation: none !important;
    }
}
```

## 🎨 Customization

### Adding New Themes

1. **Define CSS Variables**:
```css
.theme-custom {
    --bg-primary: #your-color !important;
    --text-primary: #your-text-color !important;
}
```

2. **Add to Theme Options**:
```python
theme_options = {
    "🌓 Auto": "auto",
    "☀️ Light": "light", 
    "🌙 Dark": "dark",
    "🎨 Custom": "custom"  # New theme
}
```

### Custom Components

Create themed components using CSS classes:

```python
# Themed button
st.markdown('<button class="modern-button">Click me</button>', unsafe_allow_html=True)

# Themed card
st.markdown('<div class="modern-card">Content</div>', unsafe_allow_html=True)
```

## 🔧 Troubleshooting

### Common Issues

1. **Theme not switching**: Check if CSS is properly applied
2. **Text not visible**: Ensure CSS variables are defined
3. **Mobile layout issues**: Verify responsive CSS is working

### Debug Mode

Add this to see current theme:
```python
st.write(f"Current theme: {st.session_state.theme}")
```

## 📄 License

This project is open source and available under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

If you have any questions or issues, please open an issue on GitHub.

---

**Built with ❤️ using Streamlit**
