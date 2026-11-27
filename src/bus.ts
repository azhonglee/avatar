import { EventEmitter } from "node:events";

/**
 * 进程内事件总线：账本变化、候选任务产生等。只用于“提示”（刷新 SSE、更新卡片），
 * 正确性不依赖它——跨进程的变化由控制台轮询、卡片在下一次变化或对账时补齐。
 */
export interface BusEvents {
  /** 账本里一项工作发生了变化（入队、状态迁移、取消请求、重新激活） */
  "work.changed": { id: string; kind: string; ref: string; state: string; terminal: boolean };
  /** 分诊识别出候选任务并已建卡 */
  "candidate.created": { signalId: string; taskGuid: string; summary: string; section: string };
  /** 一条飞书写入（outbox effect）落定：成功、跳过或重试耗尽。ref 是产生它的工作 */
  "effect.settled": { id: string; ref: string; state: string };
  /** 命令执行完成（审计已写入） */
  "command.executed": { name: string; source: string; ok: boolean; target: string };
}

export type BusEvent = keyof BusEvents;

export class Bus {
  private ee = new EventEmitter();
  constructor() {
    this.ee.setMaxListeners(50);
  }
  on<E extends BusEvent>(event: E, fn: (payload: BusEvents[E]) => void): () => void {
    const wrapped = (p: BusEvents[E]) => {
      try {
        fn(p);
      } catch {
        // 监听者的错误不影响发出者
      }
    };
    this.ee.on(event, wrapped);
    return () => this.ee.off(event, wrapped);
  }
  emit<E extends BusEvent>(event: E, payload: BusEvents[E]): void {
    this.ee.emit(event, payload);
  }
}
