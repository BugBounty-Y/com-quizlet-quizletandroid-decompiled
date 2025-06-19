package coil3.disk;

import androidx.browser.customtabs.k;
import java.io.IOException;
import java.util.ArrayList;
import okio.x;

/* loaded from: classes.dex */
public final class a {
    public final String a;
    public final long[] b;
    public final ArrayList c;
    public final ArrayList d;
    public boolean e;
    public boolean f;
    public k g;
    public int h;
    public final /* synthetic */ e i;

    public a(e eVar, String str) {
        this.i = eVar;
        this.a = str;
        eVar.getClass();
        this.b = new long[2];
        eVar.getClass();
        this.c = new ArrayList(2);
        eVar.getClass();
        this.d = new ArrayList(2);
        StringBuilder sb = new StringBuilder(str);
        sb.append('.');
        int length = sb.length();
        eVar.getClass();
        for (int i = 0; i < 2; i++) {
            sb.append(i);
            this.c.add(this.i.a.e(sb.toString()));
            sb.append(".tmp");
            this.d.add(this.i.a.e(sb.toString()));
            sb.setLength(length);
        }
    }

    public final b a() {
        if (this.e && this.g == null && !this.f) {
            ArrayList arrayList = this.c;
            int size = arrayList.size();
            int i = 0;
            while (true) {
                e eVar = this.i;
                if (i >= size) {
                    this.h++;
                    return new b(eVar, this);
                }
                if (eVar.q.p((x) arrayList.get(i))) {
                    i++;
                } else {
                    try {
                        eVar.y(this);
                        return null;
                    } catch (IOException unused) {
                    }
                }
            }
        }
        return null;
    }
}
