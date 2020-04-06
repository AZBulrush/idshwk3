global relaT:table[addr] of string = table();
global countT:table[addr] of int = table();

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	local ug:string = to_lower(c$http$user_agent);
	if( c$id$resp_h in relaT)
	{
		if(ug == relaT[c$id$resp_h]){
			countT[c$id$resp_h]=1;
		}
		else{
			countT[c$id$resp_h]+=1;
		}
	}
	else{
		relaT[c$id$resp_h]=ug;
		countT[c$id$resp_h]=1;
	}
}

event zeek_done()
{
	for( s , val in countT){
		if(val >= 3){
			print fmt(" %s is a proxy", s );
		}
	}
}
			