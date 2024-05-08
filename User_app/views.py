#from django.shortcuts import render, redirect
from urllib import response
from django.contrib import messages
from django.contrib.auth.models import User, auth
from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .models import CustomUser,Profile , Employer_Profile
from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model
from django.contrib.auth import login as auth_login 
from django.contrib.auth.hashers import check_password
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.shortcuts import get_object_or_404
from .models import Employer_Profile
import json
@csrf_exempt
def login(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')
        try:
            user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            user = None

        if user is not None and check_password(password, user.password):
            auth_login(request, user)  # Use Django's login function
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'gender': user.gender,  # Assuming gender is a field in CustomUser
                'contact_number': user.contact_number,  # Assuming contact_number is a field in CustomUser
            }
            refresh = RefreshToken.for_user(user)
            response_data = {
                'success': True,
                'message': 'Login successful',
                'user_data': user_data,
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'Code': "200"}
            # return render(request,'dashboard.html')
            
            return JsonResponse(response_data)
        else:
            response_data = {
                'success': False,
                'message': 'Invalid credentials',
            }
            return JsonResponse(response_data)
    else:
        response_data = {
            'message': 'Please use POST method for login',
        }
        return render(request, 'login.html')


from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
def register(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            first_name = data.get('first_name')
            last_name = data.get('last_name')
            username = data.get('username')
            email = data.get('email')
            gender = data.get('gender')
            contact_number = data.get('contact_number')  # Corrected field name
            password1 = data.get('password1')
            password2 = data.get('password2')

            if password1 == password2:
                User = get_user_model()
                if User.objects.filter(username=username).exists():
                    return JsonResponse({'error': 'Username Taken'}, status=400)
                elif User.objects.filter(email=email).exists():
                    return JsonResponse({'error': 'Email Taken'}, status=400)
                else:
                    user = CustomUser.objects.create_user(first_name=first_name, last_name=last_name, email=email, gender=gender, contact_number=contact_number, username=username, password=password1)
                    user.save()
                    return JsonResponse({'message': 'Successfully Registered'})
            else:
                return JsonResponse({'error': 'Passwords do not match'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)  # Return server error

    return render(request, 'register.html')





def update(request, pk):
    user = CustomUser.objects.get(id=pk)

    if request.method == "POST":
        data = json.loads(request.body)
        user.first_name = data.get('first_name')
        user.last_name = data.get('last_name')
        user.username = data.get('username')
        user.email = data.get('email')
        user.gender = data.get('gender')
        user.contact_number = data.get('contact_number')
        user.save()
        messages.success(request, "User details updated successfully")
        return redirect('dashboard')

    context = {'user': user}
    return render(request, 'update.html', context)


def dashboard(request):
    return render(request, 'dashboard.html')


def logout(request):
    logout(request)
    return redirect('login')


@csrf_exempt
def EmployerProfile(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            profile_id = data.get('profile_id')
            employer_name = data.get('employer_name')
            street_name = data.get('street_name')
            city = data.get('city')
            state = data.get('state')
            country = data.get('country')  
            zipcode = data.get('zipcode')
            email = data.get('email')
            number_of_employer = data.get('number_of_employer')
            department = data.get('department')
            
            # Check if required fields are empty
            if not profile_id or not employer_name or not email:
                return JsonResponse({'error': 'Required fields are missing'}, status=400)
            
            # Check if profile_id already exists
            if Employer_Profile.objects.filter(profile_id=profile_id).exists():
                return JsonResponse({'error': 'Profile ID already exists'}, status=400)
            
            # Check if email is already registered
            if Employer_Profile.objects.filter(email=email).exists():
                return JsonResponse({'error': 'Email already registered'}, status=400)
            
            # Create new Employer_Profile instance
            user = Employer_Profile.objects.create(profile_id=profile_id, employer_name=employer_name, street_name=street_name, city=city, state=state, country=country, zipcode=zipcode, email=email, number_of_employer=number_of_employer, department=department)
            
            return JsonResponse({'message': 'Employer Detail Successfully Registered'})
        
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)  # Return server error
    #return JsonResponse({'message': 'Employer Detail Successfully Registered'})   
    return render(request, 'Employer_Profile.html')

    