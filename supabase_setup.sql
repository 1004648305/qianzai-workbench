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


-- ============================================================
-- 附：育儿假提醒模块的数据表（可选执行）
-- ------------------------------------------------------------
-- 说明：工作台的育儿假记录默认随整份 state 一起，
--       加密后存在 workbench_state 表里（沿用现有端到端加密同步），
--       因此「不执行本段也能正常使用该模块」。
--       仅当你希望这批数据额外单独落一张表（便于在 Supabase 后台
--       直接查看/导出，或给其他系统读取）时，才执行下面语句。
--       注意：本表为明文，anon 可读写，请自行评估是否存放敏感信息。
-- ============================================================

create table if not exists parental_leave (
  id          text primary key,          -- 记录 id
  name        text not null,             -- 姓名
  dept1       text,                      -- 一级部门
  dept2       text,                      -- 二级部门
  apply_date  date,                      -- 申请日期
  birth_date  date,                      -- 出生日期
  stage_01    date,                      -- 0-1周岁（到期日）
  stage_12    date,                      -- 1-2周岁（到期日）
  stage_23    date,                      -- 2-3周岁（到期日）
  due_date    date,                      -- 到期日期
  note        text,                      -- 提示栏
  handled     boolean default false,     -- 是否已处理
  updated_at  bigint                     -- 更新时间戳（毫秒）
);

alter table parental_leave enable row level security;

drop policy if exists "anon full access" on parental_leave;
create policy "anon full access"
  on parental_leave
  for all
  to anon
  using (true)
  with check (true);

-- （可选）查看结果
-- select * from parental_leave order by due_date;
