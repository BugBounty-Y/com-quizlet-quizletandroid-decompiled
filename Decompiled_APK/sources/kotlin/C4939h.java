package kotlin;

import com.j256.ormlite.stmt.query.SimpleComparison;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;

/* renamed from: kotlin.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4939h implements k, Serializable {
    public final /* synthetic */ int a;
    public final Object b;

    public C4939h() {
        this.a = 1;
        this.b = new ArrayList();
    }

    public String a(String str) {
        StringBuilder sb = new StringBuilder(256);
        if (str != null) {
            sb.append(str);
        }
        ArrayList arrayList = (ArrayList) this.b;
        if (!arrayList.isEmpty()) {
            if (sb.length() > 0) {
                sb.append('\n');
            }
            sb.append("Exception Context:\n");
            Iterator it2 = arrayList.iterator();
            int i = 0;
            while (it2.hasNext()) {
                org.apache.commons.lang3.tuple.a aVar = (org.apache.commons.lang3.tuple.a) it2.next();
                sb.append("\t[");
                i++;
                sb.append(i);
                sb.append(':');
                aVar.getClass();
                sb.append((String) null);
                sb.append(SimpleComparison.EQUAL_TO_OPERATION);
                sb.append("null");
                sb.append("]\n");
            }
            sb.append("---------------------------------");
        }
        return sb.toString();
    }

    @Override // kotlin.k
    public Object getValue() {
        return this.b;
    }

    @Override // kotlin.k
    public boolean isInitialized() {
        return true;
    }

    public String toString() {
        switch (this.a) {
            case 0:
                return String.valueOf(this.b);
            default:
                return super.toString();
        }
    }

    public C4939h(Object obj) {
        this.a = 0;
        this.b = obj;
    }
}
