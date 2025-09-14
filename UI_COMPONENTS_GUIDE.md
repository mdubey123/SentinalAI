# 🎨 SentinelAI v2 UI Components Guide

This guide demonstrates how to use the enhanced UI components in your SentinelAI v2 Streamlit application.

## 🌟 Features

- **Dark/Light Mode Toggle** - Seamless theme switching
- **Modern Card Components** - Professional card layouts
- **Enhanced Buttons** - Multiple variants with hover effects
- **Status Cards** - Visual status indicators
- **Metric Cards** - Data visualization cards
- **Responsive Design** - Mobile-friendly layouts
- **Custom Animations** - Smooth transitions and effects
- **Glass Morphism** - Modern glass-like effects
- **Custom Scrollbars** - Styled scrollbars
- **Accessibility** - High contrast and reduced motion support

## 🚀 Quick Start

### 1. Basic Usage

```python
import streamlit as st
from app import load_custom_css, create_theme_toggle, create_card

# Load CSS
load_custom_css()

# Add theme toggle
create_theme_toggle()

# Create a card
create_card(
    title="My Card",
    content="This is card content",
    subtitle="Optional subtitle"
)
```

### 2. Theme Toggle

```python
def create_theme_toggle():
    """Create dark/light mode toggle button"""
    if 'dark_mode' not in st.session_state:
        st.session_state.dark_mode = False
    
    theme_icon = "🌙" if not st.session_state.dark_mode else "☀️"
    
    if st.button(theme_icon, key="theme_toggle"):
        st.session_state.dark_mode = not st.session_state.dark_mode
        st.rerun()
```

## 🎨 Component Examples

### Cards

#### Basic Card
```python
create_card(
    title="Basic Card",
    content="This is a basic card component with modern styling and hover effects.",
    subtitle="Card Subtitle"
)
```

#### Status Cards
```python
# Success Card
create_status_card("✅", "100", "Success", "success")

# Warning Card
create_status_card("⚠️", "5", "Warning", "warning")

# Error Card
create_status_card("❌", "2", "Error", "danger")

# Info Card
create_status_card("ℹ️", "10", "Info", "info")
```

#### Metric Cards
```python
# With positive delta
create_metric_card("1,234", "Total Scans", "+12%", "positive")

# With negative delta
create_metric_card("98.5%", "Success Rate", "-2.1%", "negative")

# Without delta
create_metric_card("45", "Active Threats", "0%", "neutral")
```

### Buttons

#### Button Variants
```python
# Primary Button (default)
st.button("Primary Button")

# Success Button
st.button("Success Button", key="success_btn")

# Warning Button
st.button("Warning Button", key="warning_btn")

# Danger Button
st.button("Danger Button", key="danger_btn")
```

#### Button Sizes
```python
# Small Button
st.markdown('<button class="btn-sm">Small Button</button>', unsafe_allow_html=True)

# Large Button
st.markdown('<button class="btn-lg">Large Button</button>', unsafe_allow_html=True)

# Extra Large Button
st.markdown('<button class="btn-xl">Extra Large Button</button>', unsafe_allow_html=True)
```

#### Icon Buttons
```python
st.markdown('<button class="icon-button">🔍</button>', unsafe_allow_html=True)
```

#### Floating Action Button
```python
st.markdown('<button class="fab">+</button>', unsafe_allow_html=True)
```

### Form Components

#### Text Input
```python
st.text_input("Text Input", placeholder="Enter text here...")
```

#### Text Area
```python
st.text_area("Text Area", placeholder="Enter longer text here...")
```

#### Select Box
```python
st.selectbox("Select Box", ["Option 1", "Option 2", "Option 3"])
```

#### Number Input
```python
st.number_input("Number Input", min_value=0, max_value=100, value=50)
```

#### File Uploader
```python
st.file_uploader("Upload Files", type=['txt', 'pdf', 'docx'], help="Upload files for analysis")
```

### Data Visualization

#### Data Tables
```python
import pandas as pd

df = pd.DataFrame({
    'Name': ['Alice', 'Bob', 'Charlie'],
    'Age': [25, 30, 35],
    'City': ['New York', 'London', 'Tokyo']
})

st.dataframe(df)
```

#### Charts
```python
import plotly.express as px

fig = px.pie(
    values=[10, 20, 30],
    names=['A', 'B', 'C'],
    title="Sample Pie Chart"
)

st.plotly_chart(fig, use_container_width=True)
```

### Alerts and Messages

```python
st.success("This is a success message!")
st.warning("This is a warning message!")
st.error("This is an error message!")
st.info("This is an info message!")
```

### Progress Indicators

```python
# Progress Bar
progress = st.progress(0.7)
st.text("70% Complete")

# Loading Animation
create_loading_animation()
```

### Expandable Content

```python
with st.expander("Click to expand"):
    st.write("This is expandable content with modern styling.")
    st.write("You can put any content here.")
```

## 🎯 Advanced Usage

### Custom HTML and CSS

```python
# Custom HTML with CSS
custom_html = """
<div class="card">
    <div class="card-header">
        <h3 class="card-title">Custom Card</h3>
    </div>
    <div class="card-content">
        <p>This is a custom card using HTML and CSS.</p>
    </div>
</div>
"""

st.markdown(custom_html, unsafe_allow_html=True)
```

### Responsive Layouts

```python
# Mobile-friendly columns
col1, col2, col3 = st.columns([1, 2, 1])

with col1:
    create_status_card("📊", "100", "Data Points", "info")

with col2:
    create_card(
        title="Main Content",
        content="This is the main content area that takes up more space."
    )

with col3:
    create_status_card("⚡", "Fast", "Performance", "success")
```

### Dark Mode Integration

```python
# Check current theme
is_dark = st.session_state.get('dark_mode', False)

# Apply theme-specific styling
theme_class = "dark" if is_dark else "light"
st.markdown(f"""
<script>
document.body.setAttribute('data-theme', '{theme_class}');
</script>
""", unsafe_allow_html=True)
```

## 🎨 CSS Customization

### CSS Variables

The application uses CSS custom properties for easy theming:

```css
:root {
    --primary: #1e293b;
    --accent: #3b82f6;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
    --background: linear-gradient(135deg, #f8fafc 0%, #e2e8f0 100%);
    --surface: rgba(255, 255, 255, 0.95);
    --text-primary: #0f172a;
    --text-secondary: #64748b;
    --border: rgba(226, 232, 240, 0.6);
    --shadow: rgba(15, 23, 42, 0.1);
    --radius-sm: 8px;
    --radius-md: 12px;
    --radius-lg: 16px;
    --radius-xl: 20px;
    --transition-fast: 0.15s cubic-bezier(0.4, 0, 0.2, 1);
    --transition-normal: 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}
```

### Custom Component Classes

```css
/* Card Components */
.card { /* Basic card styling */ }
.status-card { /* Status card styling */ }
.metric-container { /* Metric card styling */ }

/* Button Components */
.btn-sm { /* Small button */ }
.btn-lg { /* Large button */ }
.btn-xl { /* Extra large button */ }
.icon-button { /* Icon button */ }
.fab { /* Floating action button */ }

/* Form Components */
.stTextInput > div > div > input { /* Text input styling */ }
.stSelectbox > div > div > div { /* Select box styling */ }
.stFileUploader { /* File uploader styling */ }
```

## 📱 Mobile Responsiveness

The UI is fully responsive with breakpoints:

- **Desktop**: Full layout with all features
- **Tablet** (768px): Adjusted spacing and sizing
- **Mobile** (480px): Optimized for touch interaction

### Responsive Utilities

```css
@media (max-width: 768px) {
    .main .block-container {
        padding: 1rem !important;
    }
    
    .stTabs [data-baseweb="tab"] {
        padding: 0.75rem 1rem !important;
        font-size: 0.8rem !important;
    }
}

@media (max-width: 480px) {
    h1 { font-size: 1.5rem !important; }
    h2 { font-size: 1.25rem !important; }
    h3 { font-size: 1.1rem !important; }
}
```

## ♿ Accessibility Features

### High Contrast Mode
```css
@media (prefers-contrast: high) {
    :root {
        --border: rgba(0, 0, 0, 0.3);
        --shadow: rgba(0, 0, 0, 0.2);
    }
}
```

### Reduced Motion
```css
@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        animation-duration: 0.01ms !important;
        transition-duration: 0.01ms !important;
    }
}
```

### Focus Indicators
```css
*:focus {
    outline: 2px solid var(--accent);
    outline-offset: 2px;
}
```

## 🎭 Animation Examples

### Hover Effects
```css
.card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 30px var(--shadow-hover);
}

.stButton > button:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 25px var(--shadow-hover);
}
```

### Loading Animations
```css
@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

@keyframes backgroundShift {
    0%, 100% { transform: translateX(0) translateY(0); }
    25% { transform: translateX(-10px) translateY(-5px); }
    50% { transform: translateX(5px) translateY(-10px); }
    75% { transform: translateX(-5px) translateY(5px); }
}
```

## 🚀 Demo Mode

To see all components in action, run the application and check the "Show UI Components Demo" option in the sidebar. This will display all available components with examples.

## 📝 Best Practices

1. **Consistent Spacing**: Use the CSS variables for consistent spacing
2. **Color Usage**: Stick to the defined color palette
3. **Responsive Design**: Test on different screen sizes
4. **Accessibility**: Ensure proper contrast and focus indicators
5. **Performance**: Use CSS transforms instead of changing layout properties
6. **Semantic HTML**: Use proper HTML structure for better accessibility

## 🔧 Troubleshooting

### Common Issues

1. **CSS not loading**: Ensure `load_custom_css()` is called before any components
2. **Dark mode not working**: Check that `create_theme_toggle()` is called
3. **Mobile layout issues**: Verify responsive CSS is properly applied
4. **Animation performance**: Use `transform` and `opacity` for smooth animations

### Debug Mode

Add this to see CSS variable values:

```python
st.markdown("""
<script>
console.log('CSS Variables:', getComputedStyle(document.documentElement));
</script>
""", unsafe_allow_html=True)
```

## 📚 Additional Resources

- [Streamlit Documentation](https://docs.streamlit.io/)
- [CSS Custom Properties](https://developer.mozilla.org/en-US/docs/Web/CSS/Using_CSS_custom_properties)
- [Responsive Design](https://developer.mozilla.org/en-US/docs/Learn/CSS/CSS_layout/Responsive_Design)
- [Accessibility Guidelines](https://www.w3.org/WAI/WCAG21/quickref/)

---

**Happy Coding! 🎨✨**
