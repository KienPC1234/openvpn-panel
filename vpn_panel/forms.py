from django import forms
from .models import CustomUser

class RegistrationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Mật khẩu'}), label="Mật khẩu")
    confirm_password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Xác nhận mật khẩu'}), label="Xác nhận mật khẩu")

    class Meta:
        model = CustomUser
        fields = ['username', 'password', 'full_name', 'email']
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Tên đăng nhập'}),
            'full_name': forms.TextInput(attrs={'placeholder': 'Họ và Tên'}),
            'email': forms.EmailInput(attrs={'placeholder': 'Email (Không bắt buộc)'}),
        }

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get("password")
        confirm_password = cleaned_data.get("confirm_password")
        if password != confirm_password:
            raise forms.ValidationError("Mật khẩu không khớp!")
        return cleaned_data

class AdminUserCreationForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput(attrs={'placeholder': 'Mật khẩu'}), label="Mật khẩu")
    
    class Meta:
        model = CustomUser
        fields = ['username', 'password', 'full_name', 'email', 'is_vpn_enabled']
        widgets = {
            'username': forms.TextInput(attrs={'placeholder': 'Tên đăng nhập'}),
            'full_name': forms.TextInput(attrs={'placeholder': 'Họ và Tên'}),
            'email': forms.EmailInput(attrs={'placeholder': 'Email (Không bắt buộc)'}),
        }

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password"])
        if commit:
            user.save()
        return user
