from django.contrib import admin
from .models import Employee, Department, Designation
# Register your models here.

admin.site.register(Department)
admin.site.register(Designation)

@admin.register(Employee)
class EmployeeAdmin(admin.ModelAdmin):
    list_display = ('official_email','emp_id', 'name',  'designation', 'dept', 'user_type', 'emp_category', 'approved')
#
