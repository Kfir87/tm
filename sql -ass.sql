-- first query 
-- assumption - in case there are more than 1 person with the same salary, both of them will appear in the report ! the diff will be between both of them 
select d.name as department_name,
       rnked_pop.first_name,
       rnked_pop.last_name,
       rnked_pop.salary,
       (rnked_pop.salary - nvl(rnked_pop.sec_sal, 0)) as diff
  from (select e.id,
               e.first_name,
               e.last_name,
               e.DEPARTMENT_ID,
               salary,
               rank() over(partition by DEPARTMENT_ID order by SALARY desc) as rnk,
               lead(salary) OVER(partition by DEPARTMENT_ID order by SALARY desc) AS sec_sal
          from Employees e
         order by 4) rnked_pop left join DEPARTMENTS d on rnked_pop.department_id = d.id
 where rnked_pop.rnk = 1
 

--sec query 

with emp_more_than_3 as
 (select count(id) as cnt_mor_3, '1' as fk
    from Employees e
   where floor(months_between(sysdate, hire_date) / 12) > 3),

tot_emp as
 (select count(*) as cnt_tot, '1' as fk from Employees)

select round((e3.cnt_mor_3 / cnt_tot)*100,2)
  from tot_emp e, emp_more_than_3 e3
 where e.fk = e3.fk
