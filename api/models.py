from django.db import models
from django.contrib.auth.hashers import check_password as django_check_password, make_password

import uuid

# Create your models here.

# getting data from existing tables

class Employee(models.Model):
    emp_id = models.AutoField(primary_key=True)
    official_email = models.CharField(unique=True, max_length=254)
    password = models.CharField(max_length=128)
    email = models.CharField(max_length=254, blank=True, null=True)
    name = models.CharField(max_length=100)
    profile_pic = models.CharField(max_length=100, blank=True, null=True)
    dept = models.ForeignKey('Department', models.DO_NOTHING)
    designation = models.ForeignKey('Designation', models.DO_NOTHING)
    emp_category = models.CharField(max_length=20)
    user_type = models.CharField(max_length=20)
    approved = models.IntegerField()
    accessible_modules = models.ManyToManyField('Module', through='EmployeeUserAccessibleModules', blank=True)


    class Meta:
        managed = False
        db_table = 'employee_user'

    def __str__(self):
        return self.name

    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def check_password(self, raw_password):
        return django_check_password(raw_password, self.password)

class Department(models.Model):
    id = models.AutoField(primary_key=True, db_column="id")
    name = models.CharField(max_length=250)

    class Meta:
        managed = False
        db_table = 'employee_department'
    
    def __str__(self):
        return self.name
    


class Designation(models.Model):
    id = models.AutoField(primary_key=True, db_column="id")
    name = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'employee_designation'

    def __str__(self):
        return self.name
    
    
class Module(models.Model):
    id = models.AutoField(primary_key=True, db_column="id")
    name = models.CharField(max_length=100)

    class Meta:
        managed = False
        db_table = 'employee_module'

    def __str__(self):
        return self.name
    
    
class EmployeeUserAccessibleModules(models.Model):
    id = models.BigAutoField(primary_key=True)
    employee = models.ForeignKey(Employee, models.DO_NOTHING, db_column='user_id')
    module = models.ForeignKey('Module', models.DO_NOTHING)

    class Meta:
        managed = False
        db_table = 'employee_user_accessible_modules'
        unique_together = (('employee', 'module'),)
