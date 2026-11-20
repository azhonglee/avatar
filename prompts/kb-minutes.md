刚生成了一份会议妙记：「{{title}}」，minute_token = `{{minute_token}}`。

请把它整理进主人的知识库：

1. 用 `lark-cli minutes +detail --minute-tokens {{minute_token}} --summary --todo --chapter --as user` 读取纪要、待办和章节。
2. 在知识库「会议纪要」节点下新建一篇文档，标题为「YYYY-MM-DD {{title}}」，内容包含：会议结论、关键讨论点、待办（负责人/截止时间）、原妙记链接。保持简洁，不要照抄逐字稿。
3. 如果明显属于「项目」节点下某个已有项目文档，在最终回复里指出，由主人决定是否关联（不要改那篇文档）。
4. 在「变更日志」节点下追加一条记录。

最终回复：新文档链接 + 一句话摘要。
