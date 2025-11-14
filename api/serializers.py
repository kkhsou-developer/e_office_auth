from rest_framework import serializers
from .models import *


class EmployeeSerializer(serializers.ModelSerializer):
    accessible_modules = serializers.StringRelatedField(many=True)

    class Meta:
        model = Employee
        fields = ['emp_id','official_email', 'name', 'profile_pic', 'designation', 'dept', 'emp_category', 'user_type', 'accessible_modules']
    
    def to_representation(self, instance):
        data = super().to_representation(instance)
        data['designation'] = instance.designation.name if instance.designation else None
        data['dept'] = instance.dept.name if instance.dept else None
        data['profile_pic'] = instance.profile_pic.url if instance.profile_pic else None
        return data
    
