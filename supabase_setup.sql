-- ============================================================
-- 倩崽工作台 · Supabase 云端同步初始化
-- 在 Supabase 后台 → SQL Editor 里粘贴全部内容执行即可
-- ============================================================

-- 1) 建表：整份工作台状态以「密文」存进 data 列
create table if not exists workbench_state (
  id          text    primary key,   -- 固定行 id：qianzai_workbench_v1
  data        text,                  -- 端到端加密后的密文（JSON 字符串）
  updated_at  bigint                 -- 最近一次保存的时间戳（毫秒）
);

-- 2) 开启行级安全（RLS）
alter table workbench_state enable row level security;

-- 3) 放开 anon 读写：因为 data 列已是密文，明文外泄也解不开，
--    所以允许匿名角色直接访问这一行是安全的。
drop policy if exists "anon full access" on workbench_state;
create policy "anon full access"
  on workbench_state
  for all
  to anon
  using (true)
  with check (true);

-- （可选）查看初始化结果
-- select * from workbench_state;
