package com.iab.omid.library.pubmatic.internal;

import android.content.Context;
import androidx.annotation.NonNull;
import com.iab.omid.library.pubmatic.internal.d;
import java.util.Date;
import java.util.Iterator;
import org.json.JSONException;

/* loaded from: classes2.dex */
public class a implements d.a {
    private static a f = new a(new d());
    protected com.iab.omid.library.pubmatic.utils.f a = new com.iab.omid.library.pubmatic.utils.f();
    private Date b;
    private boolean c;
    private d d;
    private boolean e;

    private a(d dVar) {
        this.d = dVar;
    }

    public static a a() {
        return f;
    }

    private void c() throws JSONException {
        if (!this.c || this.b == null) {
            return;
        }
        Iterator<com.iab.omid.library.pubmatic.adsession.a> it2 = c.c().a().iterator();
        while (it2.hasNext()) {
            it2.next().getAdSessionStatePublisher().a(b());
        }
    }

    public Date b() {
        Date date = this.b;
        if (date != null) {
            return (Date) date.clone();
        }
        return null;
    }

    public void d() throws JSONException {
        Date dateA = this.a.a();
        Date date = this.b;
        if (date == null || dateA.after(date)) {
            this.b = dateA;
            c();
        }
    }

    public void a(@NonNull Context context) {
        if (this.c) {
            return;
        }
        this.d.a(context);
        this.d.a(this);
        this.d.e();
        this.e = this.d.c();
        this.c = true;
    }

    @Override // com.iab.omid.library.pubmatic.internal.d.a
    public void a(boolean z) throws JSONException {
        if (!this.e && z) {
            d();
        }
        this.e = z;
    }
}
