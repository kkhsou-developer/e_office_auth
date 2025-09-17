from django.contrib import admin
from .models import Employee, Department, Designation
# Register your models here.


@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    list_display = ('official_email','emp_id', 'name',  'designation', 'dept', 'user_type', 'emp_category', 'approved',)
    list_filter = ('dept', 'designation', 'user_type', 'emp_category', 'approved')


@admin.register(Department)
class DepartmentAdmin(admin.ModelAdmin):
    list_display = ('name', 'id')


@admin.register(Designation)
class DesignationAdmin(admin.ModelAdmin):
    list_display = ('name', 'id')
