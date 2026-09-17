-- Publish the corrected moderation disclosure as an immutable terms document.
-- A version now maps to one exact Turkish text digest, and every acceptance
-- keeps the first accepted timestamp instead of overwriting legal evidence.

begin;

set local statement_timeout = '30s';

create table private.ugc_terms_documents (
  version text primary key check (
    version ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}-v[1-9][0-9]*$'
  ),
  locale text not null check (locale = 'tr-TR'),
  document_text text not null check (char_length(document_text) between 500 and 20000),
  document_digest text not null check (document_digest ~ '^[a-f0-9]{64}$'),
  published_at timestamptz not null,
  created_at timestamptz not null default clock_timestamp(),
  unique (version, document_digest),
  constraint ugc_terms_documents_digest_matches_text check (
    document_digest = encode(
      extensions.digest(convert_to(document_text, 'UTF8'), 'sha256'),
      'hex'
    )
  )
);

alter table private.ugc_terms_documents enable row level security;
alter table private.ugc_terms_documents force row level security;
revoke all on table private.ugc_terms_documents
  from public, anon, authenticated, service_role;

create or replace function private.prevent_ugc_terms_document_mutation()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  raise exception 'Yayımlanmış kullanım koşulu belgesi değiştirilemez';
end;
$$;

create trigger prevent_ugc_terms_document_mutation
before update or delete on private.ugc_terms_documents
for each row execute function private.prevent_ugc_terms_document_mutation();

insert into private.ugc_terms_documents (
  version, locale, document_text, document_digest, published_at
)
select
  '2026-08-29-v1',
  'tr-TR',
  body,
  encode(extensions.digest(convert_to(body, 'UTF8'), 'sha256'), 'hex'),
  '2026-08-29 00:00:00+00'::timestamptz
from (values ($terms_v1$
1. Kapsam
Stokdaş, aynı işletmedeki doğrulanmış kullanıcıların ürün adı, ürün kodu, kategori, birim ve stok hareketi notu gibi içerikleri ortak çalışma alanında paylaşmasını sağlar. Bu içerikler yalnızca bağlı işletmenin yetkili kullanıcılarına gösterilir.

2. Yasak içerikler
Yasa dışı; cinsel veya çocukların istismarıyla ilişkili; şiddeti teşvik eden; tehdit, nefret, ayrımcılık, taciz ya da zorbalık içeren içerikler yasaktır. Başkasının kişisel verisini veya mahremiyetini ihlal eden, fikrî mülkiyet hakkını çiğneyen, dolandırıcılık ya da kimliğe bürünme amacı taşıyan, yanıltıcı, spam, izinsiz reklam, zararlı bağlantı veya kötü amaçlı yazılım niteliğindeki içerikler de yüklenemez.

3. Yasak davranışlar
Diğer kullanıcıları taciz etmek, stok kayıtlarını zarar verme amacıyla değiştirmek, yetkisiz hesaba veya işletme verisine erişmeye çalışmak, güvenlik önlemlerini aşmak, hesabı başkasına kullandırmak ve bildirim sistemini kötü niyetle kullanmak yasaktır. Her kullanıcı kendi hesabıyla yapılan işlemlerden sorumludur.

4. Bildirim ve moderasyon
Uygulamadaki “Bildir” seçenekleriyle ürünleri, stok hareketlerini ve hareketi yapan kullanıcıyı işletme yöneticisine bildirebilirsiniz. Bildirim; hedef kaydı, bildirim nedenini, isteğe bağlı açıklamayı, bildiren hesabı ve işlem zamanını içerir. İşletme yöneticisi bildirimi inceleyebilir; ürünü kaldırabilir, hareket notunu gizleyebilir, bildirilen çalışan hesabını devre dışı bırakabilir veya bildirimi işlem gerektirmediği gerekçesiyle kapatabilir.

5. Yaptırımlar
Yasak içeriğin kaldırılması, görünürlüğünün sınırlandırılması, hesap erişiminin askıya alınması veya sona erdirilmesi mümkündür. Ciddi ya da tekrarlanan ihlaller platform güvenliği kapsamında ayrıca incelenebilir ve hukuken gerekli hâllerde yetkili mercilerle iş birliği yapılabilir. Kötü niyetli ve tekrarlanan asılsız bildirimler de hesap kısıtlamasına yol açabilir.

6. Koşulların güncellenmesi
Güvenlik, mevzuat veya hizmet değişiklikleri nedeniyle koşullar güncellenebilir. Yeni bir sürüm yayımlandığında stok alanını kullanmaya devam etmeden önce yeniden kabulünüz istenir. Gizlilik ve veri işleme ayrıntıları Hesabım bölümündeki Gizlilik Politikası’nda açıklanır.

İletişim: tirtarismail@gmail.com
$terms_v1$::text)) as source(body)
on conflict (version) do nothing;

insert into private.ugc_terms_documents (
  version, locale, document_text, document_digest, published_at
)
select
  '2026-09-11-v2',
  'tr-TR',
  body,
  encode(extensions.digest(convert_to(body, 'UTF8'), 'sha256'), 'hex'),
  '2026-09-11 00:00:00+00'::timestamptz
from (values ($terms_v2$
1. Kapsam
Stokdaş, aynı işletmedeki doğrulanmış kullanıcıların ürün adı, ürün kodu, kategori, birim ve stok hareketi notu gibi içerikleri ortak çalışma alanında paylaşmasını sağlar. Bu içerikler yalnızca bağlı işletmenin yetkili kullanıcılarına gösterilir.

2. Yasak içerikler
Yasa dışı; cinsel veya çocukların istismarıyla ilişkili; şiddeti teşvik eden; tehdit, nefret, ayrımcılık, taciz ya da zorbalık içeren içerikler yasaktır. Başkasının kişisel verisini veya mahremiyetini ihlal eden, fikrî mülkiyet hakkını çiğneyen, dolandırıcılık ya da kimliğe bürünme amacı taşıyan, yanıltıcı, spam, izinsiz reklam, zararlı bağlantı veya kötü amaçlı yazılım niteliğindeki içerikler de yüklenemez.

3. Yasak davranışlar
Diğer kullanıcıları taciz etmek, stok kayıtlarını zarar verme amacıyla değiştirmek, yetkisiz hesaba veya işletme verisine erişmeye çalışmak, güvenlik önlemlerini aşmak, hesabı başkasına kullandırmak ve bildirim sistemini kötü niyetle kullanmak yasaktır. Her kullanıcı kendi hesabıyla yapılan işlemlerden sorumludur.

4. Bildirim ve moderasyon
Uygulamadaki “Bildir” seçenekleriyle ürünleri, stok hareketlerini ve hareketi yapan kullanıcıyı yetkili inceleme kuyruğuna bildirebilirsiniz. Bildirim; hedef kaydı, bildirim nedenini, isteğe bağlı açıklamayı, bildiren hesabı ve işlem zamanını içerir. Çalışan hesabıyla ilişkili içerikler işletme yöneticisinin inceleme kuyruğuna gider; yönetici ürünü kaldırabilir, hareket notunu gizleyebilir, bildirilen çalışan hesabını devre dışı bırakabilir veya bildirimi işlem gerektirmediği gerekçesiyle kapatabilir. İşletme yöneticisi ya da platform yöneticisi hesabıyla ilişkili içerikler, çıkar çatışmasını önlemek için yalnız yetkili Stokdaş platform inceleme kuyruğuna yönlendirilir. Platform incelemesi ürünü kaldırabilir, hareket notunu gizleyebilir, ilgili işletmeyi idari olarak askıya alabilir veya bildirimi işlem gerektirmediği gerekçesiyle kapatabilir.

5. Yaptırımlar
Yasak içeriğin kaldırılması, görünürlüğünün sınırlandırılması, hesap veya işletme erişiminin askıya alınması ya da sona erdirilmesi mümkündür. Ciddi veya tekrarlanan ihlaller platform güvenliği kapsamında ayrıca incelenebilir ve hukuken gerekli hâllerde yetkili mercilerle iş birliği yapılabilir. Kötü niyetli ve tekrarlanan asılsız bildirimler de hesap kısıtlamasına yol açabilir.

6. Koşulların güncellenmesi
Güvenlik, mevzuat veya hizmet değişiklikleri nedeniyle koşullar güncellenebilir. Yeni bir sürüm yayımlandığında stok alanını kullanmaya devam etmeden önce yeniden kabulünüz istenir. Gizlilik ve veri işleme ayrıntıları Hesabım bölümündeki Gizlilik Politikası’nda açıklanır.

İletişim: tirtarismail@gmail.com
$terms_v2$::text)) as source(body)
on conflict (version) do nothing;

alter table public.pending_account_registrations
  add column if not exists ugc_terms_digest text;

update public.pending_account_registrations pending
set ugc_terms_digest = document.document_digest
from private.ugc_terms_documents document
where pending.ugc_terms_version = document.version
  and pending.ugc_terms_digest is null;

alter table public.pending_account_registrations
  add constraint pending_registrations_ugc_terms_document_fkey
    foreign key (ugc_terms_version, ugc_terms_digest)
    references private.ugc_terms_documents(version, document_digest)
    on delete restrict;

create table private.ugc_terms_acceptances (
  profile_id uuid not null,
  organization_id uuid not null,
  terms_version text not null,
  document_digest text not null,
  acceptance_source text not null check (
    acceptance_source in ('migration', 'registration', 'in_app', 'service')
  ),
  accepted_at timestamptz not null,
  recorded_at timestamptz not null default clock_timestamp(),
  primary key (profile_id, terms_version),
  constraint ugc_terms_acceptances_profile_organization_fkey
    foreign key (profile_id, organization_id)
    references public.profiles(id, organization_id) on delete cascade,
  constraint ugc_terms_acceptances_document_fkey
    foreign key (terms_version, document_digest)
    references private.ugc_terms_documents(version, document_digest)
    on delete restrict,
  constraint ugc_terms_acceptances_time_check
    check (accepted_at <= recorded_at + interval '5 minutes')
);

create index ugc_terms_acceptances_organization_idx
  on private.ugc_terms_acceptances (organization_id, accepted_at desc);

alter table private.ugc_terms_acceptances enable row level security;
alter table private.ugc_terms_acceptances force row level security;
revoke all on table private.ugc_terms_acceptances
  from public, anon, authenticated, service_role;

-- Preserve the evidence represented by the existing denormalized profile
-- columns before installing the immutable capture trigger.
insert into private.ugc_terms_acceptances (
  profile_id, organization_id, terms_version, document_digest,
  acceptance_source, accepted_at, recorded_at
)
select
  p.id,
  p.organization_id,
  p.ugc_terms_version,
  d.document_digest,
  'migration',
  p.ugc_terms_accepted_at,
  greatest(clock_timestamp(), p.ugc_terms_accepted_at)
from public.profiles p
join private.ugc_terms_documents d on d.version = p.ugc_terms_version
where p.ugc_terms_version is not null
  and p.ugc_terms_accepted_at is not null
on conflict (profile_id, terms_version) do nothing;

create or replace function private.current_ugc_terms_version()
returns text
language sql
immutable
set search_path = ''
as $$
  select '2026-09-11-v2'::text;
$$;

create or replace function private.current_ugc_terms_digest()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select d.document_digest
  from private.ugc_terms_documents d
  where d.version = private.current_ugc_terms_version();
$$;

-- The existing locked reservation routine predates the digest column. A
-- narrow transaction-local handoff lets the new overload reuse all of its
-- Auth/tenant locking while this BEFORE trigger still makes the old overload
-- fail closed when called directly.
create or replace function private.enforce_pending_ugc_terms_document()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  handed_off_digest text := nullif(
    current_setting('stokdas.ugc_terms_digest', true), ''
  );
  expected_digest text;
begin
  if new.registration_kind = 'business_admin' then
    new.ugc_terms_digest := coalesce(new.ugc_terms_digest, handed_off_digest);
    select d.document_digest into expected_digest
    from private.ugc_terms_documents d
    where d.version = new.ugc_terms_version;
    if new.ugc_terms_version is distinct from private.current_ugc_terms_version()
       or new.ugc_terms_digest is distinct from expected_digest
       or expected_digest is distinct from private.current_ugc_terms_digest() then
      raise exception 'İşletme kaydı şart belgesi doğrulanamadı';
    end if;
  elsif new.ugc_terms_version is not null
        or new.ugc_terms_accepted_at is not null
        or new.ugc_terms_digest is not null then
    raise exception 'Çalışan kaydı şart belgesi içermemelidir';
  end if;
  return new;
end;
$$;

drop trigger if exists enforce_pending_ugc_terms_document
  on public.pending_account_registrations;
create trigger enforce_pending_ugc_terms_document
before insert or update of registration_kind, ugc_terms_version,
  ugc_terms_accepted_at, ugc_terms_digest
on public.pending_account_registrations
for each row execute function private.enforce_pending_ugc_terms_document();

create or replace function public.service_store_pending_registration(
  p_auth_user_id uuid,
  p_request_id uuid,
  p_registration_kind text,
  p_username text,
  p_email text,
  p_display_name text,
  p_organization_name text,
  p_organization_slug text,
  p_organization_id uuid,
  p_created_by uuid,
  p_ugc_terms_version text,
  p_ugc_terms_accepted_at timestamptz,
  p_ugc_terms_digest text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  pending_id uuid;
begin
  if p_registration_kind = 'business_admin'
     and p_ugc_terms_digest is distinct from private.current_ugc_terms_digest() then
    raise exception 'İşletme kaydı şart belgesi güncel değil';
  end if;
  if p_registration_kind = 'coworker' and p_ugc_terms_digest is not null then
    raise exception 'Çalışan kaydı şart belgesi içermemelidir';
  end if;

  perform set_config(
    'stokdas.ugc_terms_digest', coalesce(p_ugc_terms_digest, ''), true
  );
  pending_id := public.service_store_pending_registration(
    p_auth_user_id, p_request_id, p_registration_kind, p_username, p_email,
    p_display_name, p_organization_name, p_organization_slug,
    p_organization_id, p_created_by, p_ugc_terms_version,
    p_ugc_terms_accepted_at
  );
  perform set_config('stokdas.ugc_terms_digest', '', true);
  return pending_id;
end;
$$;

create or replace function private.capture_ugc_terms_acceptance()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  expected_digest text;
  existing private.ugc_terms_acceptances;
  acceptance_source text;
begin
  if new.ugc_terms_version is null or new.ugc_terms_accepted_at is null then
    return new;
  end if;

  if tg_op = 'UPDATE'
     and new.ugc_terms_version is not distinct from old.ugc_terms_version
     and new.ugc_terms_accepted_at is not distinct from old.ugc_terms_accepted_at then
    return new;
  end if;

  select d.document_digest into expected_digest
  from private.ugc_terms_documents d
  where d.version = new.ugc_terms_version;

  if expected_digest is null then
    raise exception 'Yayımlanmamış kullanıcı içeriği şartı kaydedilemez';
  end if;

  select * into existing
  from private.ugc_terms_acceptances a
  where a.profile_id = new.id
    and a.terms_version = new.ugc_terms_version
  for update;

  if existing.profile_id is not null then
    if existing.organization_id is distinct from new.organization_id
       or existing.document_digest is distinct from expected_digest
       or existing.accepted_at is distinct from new.ugc_terms_accepted_at then
      raise exception 'Kullanım koşulu kabul kanıtı değiştirilemez';
    end if;
    return new;
  end if;

  acceptance_source := case
    when tg_op = 'INSERT' then 'registration'
    when (select auth.uid()) = new.id then 'in_app'
    else 'service'
  end;

  insert into private.ugc_terms_acceptances (
    profile_id, organization_id, terms_version, document_digest,
    acceptance_source, accepted_at
  ) values (
    new.id, new.organization_id, new.ugc_terms_version, expected_digest,
    acceptance_source, new.ugc_terms_accepted_at
  );

  return new;
end;
$$;

drop trigger if exists capture_ugc_terms_acceptance on public.profiles;
create trigger capture_ugc_terms_acceptance
after insert or update of ugc_terms_version, ugc_terms_accepted_at
on public.profiles
for each row execute function private.capture_ugc_terms_acceptance();

revoke all on function private.current_ugc_terms_version()
  from public, anon, authenticated, service_role;
revoke all on function private.current_ugc_terms_digest()
  from public, anon, authenticated, service_role;
revoke all on function private.enforce_pending_ugc_terms_document()
  from public, anon, authenticated, service_role;
revoke all on function private.capture_ugc_terms_acceptance()
  from public, anon, authenticated, service_role;
revoke all on function private.prevent_ugc_terms_document_mutation()
  from public, anon, authenticated, service_role;

revoke all on function public.service_store_pending_registration(
  uuid, uuid, text, text, text, text, text, text, uuid, uuid, text, timestamptz
) from public, anon, authenticated, service_role;
revoke all on function public.service_store_pending_registration(
  uuid, uuid, text, text, text, text, text, text, uuid, uuid, text, timestamptz, text
) from public, anon, authenticated, service_role;
grant execute on function public.service_store_pending_registration(
  uuid, uuid, text, text, text, text, text, text, uuid, uuid, text, timestamptz, text
) to service_role;

comment on table private.ugc_terms_documents is
  'Immutable versioned Turkish UGC terms text and SHA-256 digest; not exposed through the Data API.';
comment on table private.ugc_terms_acceptances is
  'First immutable acceptance evidence for each profile and exact document version; removed with the profile.';

commit;
