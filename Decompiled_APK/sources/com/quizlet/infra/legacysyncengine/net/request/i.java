package com.quizlet.infra.legacysyncengine.net.request;

import android.content.Context;
import com.quizlet.api.model.ModelError;
import com.quizlet.api.model.ValidationError;
import com.quizlet.api.util.ApiErrorResolver;
import com.quizlet.remote.exceptions.NetException;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/* loaded from: classes3.dex */
public final class i {
    public final NetException a;
    public final Map b;
    public final Map c;

    public i(NetException netException, Map map, Map map2) {
        this.a = netException;
        this.b = map;
        this.c = map2;
    }

    public final String a(Context context) {
        NetException netException = this.a;
        if (netException != null) {
            return netException.getMessage();
        }
        Iterator it2 = this.b.keySet().iterator();
        while (it2.hasNext()) {
            Iterator it3 = ((List) it2.next()).iterator();
            if (it3.hasNext()) {
                return ApiErrorResolver.a(context, (ValidationError) it3.next());
            }
        }
        Iterator it4 = this.c.keySet().iterator();
        if (it4.hasNext()) {
            return ApiErrorResolver.a(context, (ModelError) it4.next());
        }
        return null;
    }
}
