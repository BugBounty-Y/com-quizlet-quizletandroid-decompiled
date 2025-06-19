package androidx.activity.result;

import java.util.ArrayList;
import java.util.LinkedHashMap;

/* loaded from: classes.dex */
public final class g extends b {
    public final /* synthetic */ int a;
    public final /* synthetic */ h b;
    public final /* synthetic */ String c;
    public final /* synthetic */ androidx.activity.result.contract.a d;

    public /* synthetic */ g(h hVar, String str, androidx.activity.result.contract.a aVar, int i) {
        this.a = i;
        this.b = hVar;
        this.c = str;
        this.d = aVar;
    }

    @Override // androidx.activity.result.b
    public final void a(Object obj) throws Exception {
        switch (this.a) {
            case 0:
                h hVar = this.b;
                LinkedHashMap linkedHashMap = hVar.b;
                String str = this.c;
                Object obj2 = linkedHashMap.get(str);
                androidx.activity.result.contract.a aVar = this.d;
                if (obj2 == null) {
                    throw new IllegalStateException(("Attempting to launch an unregistered ActivityResultLauncher with contract " + aVar + " and input " + obj + ". You must ensure the ActivityResultLauncher is registered before calling launch().").toString());
                }
                int iIntValue = ((Number) obj2).intValue();
                ArrayList arrayList = hVar.d;
                arrayList.add(str);
                try {
                    hVar.b(iIntValue, aVar, obj);
                    return;
                } catch (Exception e) {
                    arrayList.remove(str);
                    throw e;
                }
            default:
                h hVar2 = this.b;
                LinkedHashMap linkedHashMap2 = hVar2.b;
                String str2 = this.c;
                Object obj3 = linkedHashMap2.get(str2);
                androidx.activity.result.contract.a aVar2 = this.d;
                if (obj3 == null) {
                    throw new IllegalStateException(("Attempting to launch an unregistered ActivityResultLauncher with contract " + aVar2 + " and input " + obj + ". You must ensure the ActivityResultLauncher is registered before calling launch().").toString());
                }
                int iIntValue2 = ((Number) obj3).intValue();
                ArrayList arrayList2 = hVar2.d;
                arrayList2.add(str2);
                try {
                    hVar2.b(iIntValue2, aVar2, obj);
                    return;
                } catch (Exception e2) {
                    arrayList2.remove(str2);
                    throw e2;
                }
        }
    }

    public void b() {
        this.b.f(this.c);
    }
}
