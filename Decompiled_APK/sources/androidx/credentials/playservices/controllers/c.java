package androidx.credentials.playservices.controllers;

/* loaded from: classes.dex */
public final /* synthetic */ class c implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ c(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    /* JADX WARN: Removed duplicated region for block: B:174:0x03b6  */
    /* JADX WARN: Removed duplicated region for block: B:192:0x040b A[Catch: all -> 0x03e4, TryCatch #3 {all -> 0x03e4, blocks: (B:166:0x03a3, B:172:0x03b2, B:175:0x03b9, B:180:0x03cc, B:182:0x03d4, B:190:0x0407, B:192:0x040b, B:193:0x040d, B:197:0x041c, B:201:0x0429, B:205:0x0436, B:207:0x0443, B:211:0x0455, B:212:0x0457, B:209:0x0450, B:204:0x0434, B:200:0x0427, B:196:0x041a, B:187:0x03e8, B:189:0x03ed), top: B:286:0x03a3 }] */
    /* JADX WARN: Removed duplicated region for block: B:195:0x0419  */
    /* JADX WARN: Removed duplicated region for block: B:196:0x041a A[Catch: all -> 0x03e4, TryCatch #3 {all -> 0x03e4, blocks: (B:166:0x03a3, B:172:0x03b2, B:175:0x03b9, B:180:0x03cc, B:182:0x03d4, B:190:0x0407, B:192:0x040b, B:193:0x040d, B:197:0x041c, B:201:0x0429, B:205:0x0436, B:207:0x0443, B:211:0x0455, B:212:0x0457, B:209:0x0450, B:204:0x0434, B:200:0x0427, B:196:0x041a, B:187:0x03e8, B:189:0x03ed), top: B:286:0x03a3 }] */
    /* JADX WARN: Removed duplicated region for block: B:199:0x0426  */
    /* JADX WARN: Removed duplicated region for block: B:200:0x0427 A[Catch: all -> 0x03e4, TryCatch #3 {all -> 0x03e4, blocks: (B:166:0x03a3, B:172:0x03b2, B:175:0x03b9, B:180:0x03cc, B:182:0x03d4, B:190:0x0407, B:192:0x040b, B:193:0x040d, B:197:0x041c, B:201:0x0429, B:205:0x0436, B:207:0x0443, B:211:0x0455, B:212:0x0457, B:209:0x0450, B:204:0x0434, B:200:0x0427, B:196:0x041a, B:187:0x03e8, B:189:0x03ed), top: B:286:0x03a3 }] */
    /* JADX WARN: Removed duplicated region for block: B:203:0x0433  */
    /* JADX WARN: Removed duplicated region for block: B:204:0x0434 A[Catch: all -> 0x03e4, TryCatch #3 {all -> 0x03e4, blocks: (B:166:0x03a3, B:172:0x03b2, B:175:0x03b9, B:180:0x03cc, B:182:0x03d4, B:190:0x0407, B:192:0x040b, B:193:0x040d, B:197:0x041c, B:201:0x0429, B:205:0x0436, B:207:0x0443, B:211:0x0455, B:212:0x0457, B:209:0x0450, B:204:0x0434, B:200:0x0427, B:196:0x041a, B:187:0x03e8, B:189:0x03ed), top: B:286:0x03a3 }] */
    /* JADX WARN: Removed duplicated region for block: B:207:0x0443 A[Catch: all -> 0x03e4, TryCatch #3 {all -> 0x03e4, blocks: (B:166:0x03a3, B:172:0x03b2, B:175:0x03b9, B:180:0x03cc, B:182:0x03d4, B:190:0x0407, B:192:0x040b, B:193:0x040d, B:197:0x041c, B:201:0x0429, B:205:0x0436, B:207:0x0443, B:211:0x0455, B:212:0x0457, B:209:0x0450, B:204:0x0434, B:200:0x0427, B:196:0x041a, B:187:0x03e8, B:189:0x03ed), top: B:286:0x03a3 }] */
    /* JADX WARN: Removed duplicated region for block: B:209:0x0450 A[Catch: all -> 0x03e4, TryCatch #3 {all -> 0x03e4, blocks: (B:166:0x03a3, B:172:0x03b2, B:175:0x03b9, B:180:0x03cc, B:182:0x03d4, B:190:0x0407, B:192:0x040b, B:193:0x040d, B:197:0x041c, B:201:0x0429, B:205:0x0436, B:207:0x0443, B:211:0x0455, B:212:0x0457, B:209:0x0450, B:204:0x0434, B:200:0x0427, B:196:0x041a, B:187:0x03e8, B:189:0x03ed), top: B:286:0x03a3 }] */
    /* JADX WARN: Removed duplicated region for block: B:211:0x0455 A[Catch: all -> 0x03e4, TryCatch #3 {all -> 0x03e4, blocks: (B:166:0x03a3, B:172:0x03b2, B:175:0x03b9, B:180:0x03cc, B:182:0x03d4, B:190:0x0407, B:192:0x040b, B:193:0x040d, B:197:0x041c, B:201:0x0429, B:205:0x0436, B:207:0x0443, B:211:0x0455, B:212:0x0457, B:209:0x0450, B:204:0x0434, B:200:0x0427, B:196:0x041a, B:187:0x03e8, B:189:0x03ed), top: B:286:0x03a3 }] */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() {
        /*
            Method dump skipped, instructions count: 1566
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.credentials.playservices.controllers.c.run():void");
    }
}
