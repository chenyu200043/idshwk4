@load base/frameworks/sumstats

event http_reply(c:connection, version: string, code: count, reason: string)
{
     SumStats::observe("res_receive", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
     if(code == 404)
     {
         SumStats::observe("res_404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
         SumStats::observe("res_uni404", SumStats::Key($host=c$id$orig_h), SumStats::Observation($str=c$http$uri));
     }
}

event zeek_init()
{
    local r1 = SumStats::Reducer($stream="res_receive", $apply=set(SumStats::SUM));
    local r2 = SumStats::Reducer($stream="res_404", $apply=set(SumStats::SUM));
    local r3 = SumStats::Reducer($stream="res_uni404", $apply=set(SumStats::UNIQUE));

    SumStats::create([
                        $name="idshwk4",$epoch=10min,$reducers=set(r1, r2, r3),
                        $epoch_result(ts:time, key:SumStats::Key, result: SumStats::Result) = 
                        {
                            local r1 = result["res_receive"];
                            local r2 = result["res_404"];
                            local r3 = result["res_uni404"];
                            if(r2$sum > 2)
                            {
                                if(r2$sum / r1$sum > 0.2)
                                {
                                    if(r3$unique / r2$sum > 0.5)
                                    {
                                        print fmt("%s is a scanner with %.0f scan attemps on %d urls", key$host, r2$sum, r3$unique);
                                    }
                                }
                            }
                        }
                        ]);
}