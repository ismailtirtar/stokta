-- Store compliance: users can delete their accounts without erasing the
-- integrity of shared stock history. Deleted coworkers are anonymized.

begin;

alter table public.stock_movements
  drop constraint if exists stock_movements_actor_id_fkey;

alter table public.stock_movements
  alter column actor_id drop not null;

alter table public.stock_movements
  add constraint stock_movements_actor_id_fkey
  foreign key (actor_id) references public.profiles(id) on delete set null;

grant update, delete on table public.profiles to service_role;
grant delete on table public.products to service_role;
grant update, delete on table public.stock_movements to service_role;

commit;
