-- JALANKAN SEKALI di Supabase > SQL Editor. Buat 4 user dulu (lihat README.md), lalu jalankan skrip ini.

create table units(id serial primary key, name text unique not null);
create table profiles(
  id uuid primary key references auth.users on delete cascade,
  username text unique not null, full_name text,
  role text not null check (role in ('admin','auditor','auditee','viewer')),
  unit_id int references units(id), active boolean not null default true);
create table findings(
  id bigint generated always as identity primary key, no text,
  title text not null, description text, criteria text, cause text, impact text,
  risk text not null check (risk in ('Tinggi','Sedang','Rendah')),
  unit_id int references units(id), recommendation text, due_date date,
  status text not null default 'Open' check (status in ('Open','In Progress','Closed')),
  action_plan text, progress int not null default 0 check (progress between 0 and 100),
  created_by uuid default auth.uid(), created_at timestamptz default now());
create table activity_log(
  id bigint generated always as identity primary key, user_id uuid,
  action text, table_name text, row_id text, at timestamptz default now());

-- Fungsi bantu: role & unit user yang sedang login (null jika akun nonaktif)
create function my_role() returns text language sql stable security definer set search_path=public
as $$ select role from profiles where id=auth.uid() and active $$;
create function my_unit() returns int language sql stable security definer set search_path=public
as $$ select unit_id from profiles where id=auth.uid() and active $$;

-- Nomor temuan otomatis: TMN-2026-001
create function set_no() returns trigger language plpgsql as $$
begin new.no:='TMN-'||to_char(now(),'YYYY')||'-'||lpad(new.id::text,3,'0'); return new; end $$;
create trigger t_no before insert on findings for each row execute function set_no();

-- Auditee hanya boleh mengubah tindak lanjut (rencana, progres, status selain Closed)
create function guard() returns trigger language plpgsql as $$
declare r findings;
begin
  if my_role()='auditee' then
    r:=old; r.action_plan:=new.action_plan; r.progress:=new.progress;
    r.status:=case when new.status='Closed' then old.status else new.status end;
    return r;
  end if; return new;
end $$;
create trigger t_guard before update on findings for each row execute function guard();

-- Log aktivitas otomatis
create function log_it() returns trigger language plpgsql security definer set search_path=public as $$
begin insert into activity_log(user_id,action,table_name,row_id)
  values(auth.uid(),tg_op,tg_table_name,coalesce(new.id,old.id)::text); return null; end $$;
create trigger t_log after insert or update or delete on findings for each row execute function log_it();

-- RLS (hak akses di server)
alter table units enable row level security;
alter table profiles enable row level security;
alter table findings enable row level security;
alter table activity_log enable row level security;

create policy u_sel on units for select using (my_role() is not null);
create policy u_adm on units for all using (my_role()='admin') with check (my_role()='admin');
create policy p_sel on profiles for select using (id=auth.uid() or my_role()='admin');
create policy p_adm on profiles for all using (my_role()='admin') with check (my_role()='admin');
create policy f_sel on findings for select using (
  my_role() in ('admin','auditor','viewer') or (my_role()='auditee' and unit_id=my_unit()));
create policy f_ins on findings for insert with check (my_role() in ('admin','auditor'));
create policy f_upd on findings for update
  using (my_role() in ('admin','auditor') or (my_role()='auditee' and unit_id=my_unit()))
  with check (my_role() in ('admin','auditor') or (my_role()='auditee' and unit_id=my_unit()));
create policy f_del on findings for delete using (my_role()='admin');
create policy l_sel on activity_log for select using (my_role()='admin');

-- DATA CONTOH
insert into units(name) values('Keuangan'),('SDM'),('Operasional'),('TI');

-- Profil dari 4 akun uji: admin, auditor, pic (auditee unit Keuangan), manajemen (viewer)
insert into profiles(id,username,full_name,role,unit_id)
select id, split_part(email,'@',1), initcap(split_part(email,'@',1)),
  case split_part(email,'@',1) when 'admin' then 'admin' when 'auditor' then 'auditor'
       when 'pic' then 'auditee' else 'viewer' end,
  case when email like 'pic@%' then 1 end
from auth.users where email like '%@audit.internal';

insert into findings(title,risk,unit_id,due_date,status,recommendation) values
('Rekonsiliasi bank terlambat','Tinggi',1,current_date-5,'Open','Lakukan rekonsiliasi setiap bulan'),
('Data cuti karyawan tidak akurat','Sedang',2,current_date+10,'In Progress','Perbarui sistem cuti'),
('Stok gudang tidak sesuai catatan','Tinggi',3,current_date+30,'Open','Lakukan stock opname rutin'),
('Hak akses sistem tidak ditinjau','Rendah',4,current_date-20,'Closed','Tinjau hak akses tiap kuartal');
