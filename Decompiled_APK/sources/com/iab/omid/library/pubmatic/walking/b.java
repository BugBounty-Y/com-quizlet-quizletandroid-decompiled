package com.iab.omid.library.pubmatic.walking;

import com.iab.omid.library.pubmatic.walking.async.b;
import com.iab.omid.library.pubmatic.walking.async.d;
import com.iab.omid.library.pubmatic.walking.async.e;
import com.iab.omid.library.pubmatic.walking.async.f;
import java.util.HashSet;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public class b implements b.InterfaceC0006b {
    private JSONObject a;
    private final com.iab.omid.library.pubmatic.walking.async.c b;

    public b(com.iab.omid.library.pubmatic.walking.async.c cVar) {
        this.b = cVar;
    }

    @Override // com.iab.omid.library.pubmatic.walking.async.b.InterfaceC0006b
    public JSONObject a() {
        return this.a;
    }

    public void b() {
        this.b.b(new d(this));
    }

    @Override // com.iab.omid.library.pubmatic.walking.async.b.InterfaceC0006b
    public void a(JSONObject jSONObject) {
        this.a = jSONObject;
    }

    public void b(JSONObject jSONObject, HashSet<String> hashSet, long j) {
        this.b.b(new f(this, hashSet, jSONObject, j));
    }

    public void a(JSONObject jSONObject, HashSet<String> hashSet, long j) {
        this.b.b(new e(this, hashSet, jSONObject, j));
    }
}
