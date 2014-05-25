架构：
	当前目录下rebar.config大致内容
	==============================
	{sub_dirs, ["rel"]}.  #这里rel根据你实际目录确定如果不做release，其实下面一句就够了
	{erl_opts, [debug_info]}.
	==============================
	命令行输入
	rebar compile 
	可以编译到ebin

	如果想要构建release版本，需要mkdir rel，然后在rel下面使用
	rebar create-node nodeid=h323_app 
	注意这里是nodeid，不是appid

	注意在       
	{app, h323_app, [{mod_cond, app}, {incl_cond, include},
			{lib_dir, ".."}]}
	中lib_dir是根据情况添加的，我们这里是父目录。
	现在如果想release，就可以直接用 rebar compile release了。


运行：
	在erl命令行中
		application:start(h323_app).
		h323_server:h323Test().
	就可以测试了。目前是简单的去gk那里注册和注销
