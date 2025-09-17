from django.db import models

# Create your models here.

# getting data from existing tables

class Employee(models.Model):
    emp_id = models.AutoField(primary_key=True)
    official_email = models.CharField(unique=True, max_length=254)
    email = models.CharField(max_length=254, blank=True, null=True)
    name = models.CharField(max_length=100)
    profile_pic = models.CharField(max_length=100, blank=True, null=True)
    dept = models.ForeignKey('Department', models.DO_NOTHING)
    designation = models.ForeignKey('Designation', models.DO_NOTHING)
    emp_category = models.CharField(max_length=20)
    user_type = models.CharField(max_length=20)
    approved = models.IntegerField()

    class Meta:
        managed = False
        db_table = 'employee_user'

    def __str__(self):
        return self.name

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
    
    