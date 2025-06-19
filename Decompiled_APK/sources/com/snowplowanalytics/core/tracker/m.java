package com.snowplowanalytics.core.tracker;

/* loaded from: classes3.dex */
public final class m {
    public final /* synthetic */ int a;
    public final /* synthetic */ n b;

    public /* synthetic */ m(n nVar, int i) {
        this.a = i;
        this.b = nVar;
    }

    /*  JADX ERROR: JadxRuntimeException in pass: SimplifyVisitor
        jadx.core.utils.exceptions.JadxRuntimeException: Can't remove SSA var: r6v5 boolean, still in use, count: 3, list:
          (r6v5 boolean) from 0x00b5: INVOKE 
          (wrap:java.util.concurrent.atomic.AtomicBoolean:0x00b3: IGET (r2v4 com.snowplowanalytics.core.session.c) A[WRAPPED] com.snowplowanalytics.core.session.c.f java.util.concurrent.atomic.AtomicBoolean)
          (r6v5 boolean)
          (r1v11 boolean)
         VIRTUAL call: java.util.concurrent.atomic.AtomicBoolean.compareAndSet(boolean, boolean):boolean A[MD:(boolean, boolean):boolean (c), WRAPPED]
          (r6v5 boolean) from 0x0088: IF  (r6v5 boolean) == true  -> B:40:0x008a A[HIDDEN]
          (r6v5 boolean) from 0x00c1: IF  (r6v5 boolean) != true  -> B:53:0x00ea A[HIDDEN]
        	at jadx.core.utils.InsnRemover.removeSsaVar(InsnRemover.java:162)
        	at jadx.core.utils.InsnRemover.unbindResult(InsnRemover.java:127)
        	at jadx.core.utils.InsnRemover.unbindInsn(InsnRemover.java:91)
        	at jadx.core.utils.InsnRemover.unbindArgUsage(InsnRemover.java:174)
        	at jadx.core.utils.InsnRemover.unbindAllArgs(InsnRemover.java:106)
        	at jadx.core.utils.InsnRemover.unbindInsn(InsnRemover.java:90)
        	at jadx.core.utils.InsnRemover.unbindArgUsage(InsnRemover.java:174)
        	at jadx.core.dex.instructions.args.InsnArg.wrapInstruction(InsnArg.java:141)
        	at jadx.core.dex.visitors.SimplifyVisitor.simplifyArgs(SimplifyVisitor.java:116)
        	at jadx.core.dex.visitors.SimplifyVisitor.simplifyInsn(SimplifyVisitor.java:132)
        	at jadx.core.dex.visitors.SimplifyVisitor.simplifyBlock(SimplifyVisitor.java:86)
        	at jadx.core.dex.visitors.SimplifyVisitor.visit(SimplifyVisitor.java:71)
        */
    public final void a(java.util.HashMap r6) {
        /*
            Method dump skipped, instructions count: 338
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.snowplowanalytics.core.tracker.m.a(java.util.HashMap):void");
    }
}
