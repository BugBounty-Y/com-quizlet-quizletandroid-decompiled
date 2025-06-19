package com.android.billingclient.api;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3343g2;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.db.data.models.persisted.fields.DBStudySetFields;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import kotlin.Pair;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.D;
import kotlin.text.StringsKt;
import org.json.JSONArray;
import org.json.JSONObject;

/* loaded from: classes.dex */
public final class h implements io.reactivex.rxjava3.functions.h {
    public final ArrayList a;

    public h(ArrayList arrayList) {
        this.a = arrayList;
    }

    public void a(String name, String value) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
        AbstractC3343g2.b(name);
        AbstractC3343g2.c(value, name);
        b(name, value);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        Long userId = (Long) obj;
        Intrinsics.checkNotNullParameter(userId, "userId");
        com.quizlet.infra.legacysyncengine.orm.b bVar = new com.quizlet.infra.legacysyncengine.orm.b(Models.STUDY_SET);
        bVar.c(DBStudySetFields.ID, new HashSet(this.a), null);
        return new Pair(userId, new com.quizlet.qutils.data.offline.d(bVar.a(), com.quizlet.qutils.data.offline.c.a, false, com.quizlet.qutils.data.offline.b.c, com.quizlet.qutils.data.offline.a.b));
    }

    public void b(String name, String value) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
        ArrayList arrayList = this.a;
        arrayList.add(name);
        arrayList.add(StringsKt.g0(value).toString());
    }

    public void c(String name, String value) {
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(value, "value");
        if (name.length() <= 0) {
            throw new IllegalArgumentException("name is empty");
        }
        int length = name.length();
        for (int i = 0; i < length; i++) {
            char cCharAt = name.charAt(i);
            if ('!' > cCharAt || cCharAt >= 127) {
                throw new IllegalArgumentException(okhttp3.internal.b.j("Unexpected char %#04x at %d in header name: %s", Integer.valueOf(cCharAt), Integer.valueOf(i), name).toString());
            }
        }
        b(name, value);
    }

    public okhttp3.r d() {
        return new okhttp3.r((String[]) this.a.toArray(new String[0]));
    }

    public synchronized ArrayList e(Class cls, Class cls2) {
        ArrayList arrayList = new ArrayList();
        if (cls2.isAssignableFrom(cls)) {
            arrayList.add(cls2);
            return arrayList;
        }
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            com.bumptech.glide.load.resource.transcode.c cVar = (com.bumptech.glide.load.resource.transcode.c) it2.next();
            if ((cVar.a.isAssignableFrom(cls) && cls2.isAssignableFrom(cVar.b)) && !arrayList.contains(cVar.b)) {
                arrayList.add(cVar.b);
            }
        }
        return arrayList;
    }

    public void f(String name) {
        Intrinsics.checkNotNullParameter(name, "name");
        int i = 0;
        while (true) {
            ArrayList arrayList = this.a;
            if (i >= arrayList.size()) {
                return;
            }
            if (D.l(name, (String) arrayList.get(i), true)) {
                arrayList.remove(i);
                arrayList.remove(i);
                i -= 2;
            }
            i += 2;
        }
    }

    public h(JSONArray jSONArray) {
        ArrayList arrayList = new ArrayList();
        if (jSONArray != null) {
            for (int i = 0; i < jSONArray.length(); i++) {
                JSONObject jSONObjectOptJSONObject = jSONArray.optJSONObject(i);
                if (jSONObjectOptJSONObject != null) {
                    arrayList.add(new g(jSONObjectOptJSONObject));
                }
            }
        }
        this.a = arrayList;
    }

    public h(int i) {
        switch (i) {
            case 3:
                this.a = new ArrayList(20);
                break;
            default:
                this.a = new ArrayList();
                break;
        }
    }
}
