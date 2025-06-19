package com.quizlet.infra.legacysyncengine.net.request;

import com.quizlet.remote.exceptions.NetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes3.dex */
public final class c {
    public static final c b = new c(new ArrayList());
    public final List a;

    public c(List list) {
        this.a = list;
    }

    public final i a() {
        ArrayList arrayList = new ArrayList();
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            arrayList.add(((h) it2.next()).b);
        }
        HashMap map = new HashMap();
        HashMap map2 = new HashMap();
        Iterator it3 = arrayList.iterator();
        NetException netException = null;
        while (it3.hasNext()) {
            i iVar = (i) it3.next();
            NetException netException2 = iVar.a;
            if (netException2 != null) {
                netException = netException2;
            }
            Map map3 = iVar.b;
            if (map3 != null) {
                map.putAll(map3);
            }
            Map map4 = iVar.c;
            if (map4 != null) {
                map2.putAll(map4);
            }
        }
        return new i(netException, map, map2);
    }

    public final boolean b() {
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            i iVar = ((h) it2.next()).b;
            Map map = iVar.b;
            if (map != null && map.size() > 0) {
                return true;
            }
            Map map2 = iVar.c;
            if ((map2 != null && map2.size() > 0) || iVar.a != null) {
                return true;
            }
        }
        return false;
    }
}
