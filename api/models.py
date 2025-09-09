from django.db import models
from django.contrib.auth.models import AbstractUser
from .manager import EmployeeManager

# Create your models here.



class Employee(AbstractUser):

    EMP_CATEGORY = [
        ('Examination', 'Examination'),
        ('Non Academic', 'Non Academic'),
        ('Academic', 'Academic'),
        ('Permanent', 'Permanent'),
        ('Contractual', 'Contractual'),
        ('Technical', 'Technical'),
        ('Others', 'Others'),
    ]

    USER_TYPE = [
        ('Admin', 'Admin'),
        ('Employee', 'Employee'),
    ]


    username = None
    first_name = None
    last_name = None

    emp_id = models.AutoField(primary_key=True)
    official_email = models.EmailField(max_length=254, unique=True, help_text="Official email ending with kkhsou.in")
    email = models.EmailField(max_length=254, blank=True, null=True, help_text="Personal email id")
    phone = models.CharField(max_length=10, help_text="10 digit phone number", blank=True, null=True)
    mobile = models.CharField(max_length=10, help_text="10 digit mobile number", blank=True, null=True)

    name = models.CharField(max_length=100)
    profile_pic = models.ImageField(upload_to='profile_pics/', null=True, blank=True)
    designation = models.ForeignKey("Designation", on_delete=models.CASCADE, db_column="designation_id")
    dept = models.ForeignKey("Department", on_delete=models.CASCADE)

    dob = models.DateField(help_text="Date of Birth", null=True, blank=True)
    doj = models.DateField(help_text="Date of Joining", null=True, blank=True)
    aoc = models.CharField(max_length=255, help_text="Address of the coresspondance", null=True, blank=True)
    aos = models.CharField(max_length=255, help_text="Area of Specialization", null=True, blank=True)

    emp_category = models.CharField(max_length=20, choices=EMP_CATEGORY)
    user_type = models.CharField(max_length=20, choices=USER_TYPE, default='Employee')
    approved = models.BooleanField(default=False)

    USERNAME_FIELD = 'official_email'
    REQUIRED_FIELDS = []
    objects = EmployeeManager()

    @property
    def id(self):
        return self.emp_id
    
    def __str__(self):
        return self.name



# getting data from existing tables
class Designation(models.Model):
    desig_slno = models.AutoField(primary_key=True, db_column="Desig_Slno")
    desig_code = models.CharField(max_length=45,db_column="Desig_code")
    desig_name = models.CharField(max_length=45,db_column="Desig_name")
    
    class Meta:
        db_table = "designation"
        managed = False

    def __str__(self):
        return self.desig_name
    
    
class Department(models.Model):
    dept_slno = models.AutoField(primary_key=True, db_column="Dept_Slno")
    dept_code = models.CharField(max_length=45,db_column="Dept_code")
    dept_name = models.CharField(max_length=1000,db_column="Dept_name")
    
    class Meta:
        db_table = "department"
        managed = False

    def __str__(self):
        return self.dept_name

