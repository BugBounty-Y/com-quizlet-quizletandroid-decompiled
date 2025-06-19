package com.quizlet.quizletandroid.ui.common.images.capture;

import android.app.Activity;
import android.content.Context;
import android.net.Uri;
import androidx.work.impl.t;
import com.facebook.appevents.g;
import com.google.android.gms.internal.mlkit_vision_barcode.E0;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.quizlet.data.model.C4113b2;
import com.quizlet.data.model.C4154o1;
import com.quizlet.data.model.SimpleImage;
import com.quizlet.data.model.Solution;
import com.quizlet.data.model.SolutionColumn;
import com.quizlet.data.model.SolutionColumnImage;
import com.quizlet.data.model.SolutionColumnImages;
import com.quizlet.data.model.SolutionStep;
import com.quizlet.data.model.Textbook;
import com.quizlet.data.model.Z;
import com.quizlet.quizletandroid.ui.profile.p;
import com.quizlet.remote.model.explanations.RemoteSimpleImage;
import com.quizlet.remote.model.explanations.solution.RemoteSolution;
import com.quizlet.remote.model.explanations.solution.RemoteSolutionColumn;
import com.quizlet.remote.model.explanations.solution.RemoteSolutionColumnImage;
import com.quizlet.remote.model.explanations.solution.RemoteSolutionColumnImages;
import com.quizlet.remote.model.explanations.solution.RemoteSolutionStep;
import com.quizlet.search.data.newsearch.d;
import com.quizlet.search.data.newsearch.e;
import com.quizlet.search.data.newsearch.f;
import io.reactivex.rxjava3.functions.h;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.NoWhenBranchMatchedException;
import kotlin.collections.C;
import kotlin.jvm.internal.Intrinsics;
import okio.C5088e;

/* loaded from: classes3.dex */
public final class a implements com.quizlet.qutils.image.capture.a, com.quizlet.remote.mapper.base.a, h {
    public a(p remoteSimpleImageMapper) {
        Intrinsics.checkNotNullParameter(remoteSimpleImageMapper, "remoteSimpleImageMapper");
    }

    public static final void f(C5088e c5088e, long j, boolean z) {
        C5088e c5088e2;
        ReentrantLock reentrantLock = C5088e.h;
        if (C5088e.l == null) {
            C5088e.l = new C5088e();
            com.bumptech.glide.load.engine.executor.a aVar = new com.bumptech.glide.load.engine.executor.a("Okio Watchdog");
            aVar.setDaemon(true);
            aVar.start();
        }
        long jNanoTime = System.nanoTime();
        if (j != 0 && z) {
            c5088e.g = Math.min(j, c5088e.c() - jNanoTime) + jNanoTime;
        } else if (j != 0) {
            c5088e.g = j + jNanoTime;
        } else {
            if (!z) {
                throw new AssertionError();
            }
            c5088e.g = c5088e.c();
        }
        long j2 = c5088e.g - jNanoTime;
        C5088e c5088e3 = C5088e.l;
        Intrinsics.d(c5088e3);
        while (true) {
            c5088e2 = c5088e3.f;
            if (c5088e2 == null || j2 < c5088e2.g - jNanoTime) {
                break;
            }
            Intrinsics.d(c5088e2);
            c5088e3 = c5088e2;
        }
        c5088e.f = c5088e2;
        c5088e3.f = c5088e;
        if (c5088e3 == C5088e.l) {
            C5088e.i.signal();
        }
    }

    public static C5088e g() throws InterruptedException {
        C5088e c5088e = C5088e.l;
        Intrinsics.d(c5088e);
        C5088e c5088e2 = c5088e.f;
        if (c5088e2 == null) {
            long jNanoTime = System.nanoTime();
            C5088e.i.await(C5088e.j, TimeUnit.MILLISECONDS);
            C5088e c5088e3 = C5088e.l;
            Intrinsics.d(c5088e3);
            if (c5088e3.f != null || System.nanoTime() - jNanoTime < C5088e.k) {
                return null;
            }
            return C5088e.l;
        }
        long jNanoTime2 = c5088e2.g - System.nanoTime();
        if (jNanoTime2 > 0) {
            C5088e.i.await(jNanoTime2, TimeUnit.NANOSECONDS);
            return null;
        }
        C5088e c5088e4 = C5088e.l;
        Intrinsics.d(c5088e4);
        c5088e4.f = c5088e2.f;
        c5088e2.f = null;
        c5088e2.e = 2;
        return c5088e2;
    }

    public static com.quizlet.ui.models.search.a j(a aVar, f fVar, LinkedHashSet linkedHashSet, boolean z, int i) {
        if ((i & 2) != 0) {
            linkedHashSet = null;
        }
        if ((i & 4) != 0) {
            z = false;
        }
        aVar.getClass();
        if (fVar instanceof com.quizlet.search.data.newsearch.a) {
            com.quizlet.search.data.newsearch.a aVar2 = (com.quizlet.search.data.newsearch.a) fVar;
            Intrinsics.e(aVar2, "null cannot be cast to non-null type com.quizlet.search.data.newsearch.SearchAd");
            Intrinsics.checkNotNullParameter(aVar2, "<this>");
            com.quizlet.search.ads.b bVar = aVar2.a;
            return new com.quizlet.ui.models.content.ads.a(bVar != null ? bVar.a : null);
        }
        if (fVar instanceof d) {
            d dVar = (d) fVar;
            Intrinsics.e(dVar, "null cannot be cast to non-null type com.quizlet.search.data.newsearch.set.NewSearchStudySet");
            C4113b2 c4113b2 = ((com.quizlet.search.data.newsearch.set.a) dVar).a;
            if (linkedHashSet != null) {
                linkedHashSet.add(Long.valueOf(c4113b2.a.a));
            }
            return E0.d(c4113b2);
        }
        if (fVar instanceof com.quizlet.search.data.newsearch.b) {
            com.quizlet.search.data.newsearch.b bVar2 = (com.quizlet.search.data.newsearch.b) fVar;
            Intrinsics.e(bVar2, "null cannot be cast to non-null type com.quizlet.search.data.newsearch.classes.NewSearchClass");
            return E0.b(((com.quizlet.search.data.newsearch.classes.a) bVar2).a);
        }
        if (!(fVar instanceof com.quizlet.search.data.newsearch.c)) {
            if (!(fVar instanceof e)) {
                throw new NoWhenBranchMatchedException();
            }
            e eVar = (e) fVar;
            Intrinsics.e(eVar, "null cannot be cast to non-null type com.quizlet.search.data.newsearch.user.NewSearchUser");
            return E0.f(((com.quizlet.search.data.newsearch.user.a) eVar).a);
        }
        com.quizlet.search.data.newsearch.c cVar = (com.quizlet.search.data.newsearch.c) fVar;
        Intrinsics.e(cVar, "null cannot be cast to non-null type com.quizlet.search.data.newsearch.explanations.NewSearchExplanations");
        Z z2 = ((com.quizlet.search.data.newsearch.explanations.a) cVar).a;
        if (z2 instanceof C4154o1) {
            return E0.c(z2, z);
        }
        if (z2 instanceof Textbook) {
            return E0.e(z2, z);
        }
        throw new IllegalArgumentException("Invalid type for UI model " + z2);
    }

    public static void k(Activity activity, String str) {
        File databasePath = activity.getDatabasePath("snowplowEvents.sqlite");
        File databasePath2 = activity.getDatabasePath("snowplowEvents.sqlite-wal");
        File databasePath3 = activity.getDatabasePath("snowplowEvents.sqlite-shm");
        File parentFile = databasePath.getParentFile();
        File file = new File(parentFile, str);
        File file2 = new File(parentFile, android.support.v4.media.session.a.k(str, "-wal"));
        File file3 = new File(parentFile, android.support.v4.media.session.a.k(str, "-shm"));
        if (databasePath.renameTo(file) && databasePath2.renameTo(file2)) {
            databasePath3.renameTo(file3);
        }
    }

    @Override // com.quizlet.qutils.image.capture.a
    public File a(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        return b(context, "jpg");
    }

    /* JADX WARN: Code restructure failed: missing block: B:23:0x0085, code lost:
    
        r3.add(new com.quizlet.data.model.C4177w1(r6, r10));
     */
    @Override // io.reactivex.rxjava3.functions.h
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object apply(java.lang.Object r13) {
        /*
            r12 = this;
            com.quizlet.remote.model.base.ApiThreeWrapper r13 = (com.quizlet.remote.model.base.ApiThreeWrapper) r13
            java.lang.String r0 = "response"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r13, r0)
            java.util.List r13 = r13.a
            if (r13 == 0) goto La9
            java.lang.String r0 = "remotes"
            java.util.ArrayList r0 = assistantMode.refactored.a.m(r0, r13)
            java.util.Iterator r13 = r13.iterator()
        L15:
            boolean r1 = r13.hasNext()
            if (r1 == 0) goto La4
            java.lang.Object r1 = r13.next()
            com.quizlet.remote.model.school.memberships.SchoolMembershipResponse r1 = (com.quizlet.remote.model.school.memberships.SchoolMembershipResponse) r1
            java.lang.String r2 = "remote"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r1, r2)
            com.quizlet.remote.model.school.memberships.SchoolMembershipResponse$SchoolMembershipModels r2 = r1.d
            java.util.List r2 = r2.b
            java.util.ArrayList r3 = new java.util.ArrayList
            r4 = 10
            int r4 = kotlin.collections.C.q(r2, r4)
            r3.<init>(r4)
            java.util.Iterator r2 = r2.iterator()
        L39:
            boolean r4 = r2.hasNext()
            if (r4 == 0) goto L9f
            java.lang.Object r4 = r2.next()
            com.quizlet.remote.model.school.memberships.RemoteSchoolMembership r4 = (com.quizlet.remote.model.school.memberships.RemoteSchoolMembership) r4
            com.quizlet.remote.model.school.memberships.SchoolMembershipResponse$SchoolMembershipModels r5 = r1.d
            java.util.List r5 = r5.a
            java.util.Iterator r5 = r5.iterator()
        L4d:
            boolean r6 = r5.hasNext()
            if (r6 == 0) goto L63
            java.lang.Object r6 = r5.next()
            r7 = r6
            com.quizlet.remote.model.school.RemoteSchool r7 = (com.quizlet.remote.model.school.RemoteSchool) r7
            long r7 = r7.a
            long r9 = r4.b
            int r7 = (r7 > r9 ? 1 : (r7 == r9 ? 0 : -1))
            if (r7 != 0) goto L4d
            goto L64
        L63:
            r6 = 0
        L64:
            com.quizlet.remote.model.school.RemoteSchool r6 = (com.quizlet.remote.model.school.RemoteSchool) r6
            if (r6 == 0) goto L97
            com.quizlet.data.model.w1 r5 = new com.quizlet.data.model.w1
            com.quizlet.data.model.School r6 = com.quizlet.remote.model.school.a.a(r6)
            com.quizlet.generated.enums.T1 r7 = com.quizlet.generated.enums.U1.Companion
            int r4 = r4.c
            r7.getClass()
            com.quizlet.generated.enums.U1[] r7 = com.quizlet.generated.enums.U1.values()
            int r8 = r7.length
            r9 = 0
        L7b:
            if (r9 >= r8) goto L8f
            r10 = r7[r9]
            int r11 = r10.a()
            if (r11 != r4) goto L8c
            r5.<init>(r6, r10)
            r3.add(r5)
            goto L39
        L8c:
            int r9 = r9 + 1
            goto L7b
        L8f:
            java.util.NoSuchElementException r13 = new java.util.NoSuchElementException
            java.lang.String r0 = "Array contains no element matching the predicate."
            r13.<init>(r0)
            throw r13
        L97:
            java.util.NoSuchElementException r13 = new java.util.NoSuchElementException
            java.lang.String r0 = "School not found"
            r13.<init>(r0)
            throw r13
        L9f:
            kotlin.collections.G.u(r0, r3)
            goto L15
        La4:
            io.reactivex.rxjava3.internal.operators.flowable.b r13 = io.reactivex.rxjava3.core.p.f(r0)
            return r13
        La9:
            java.util.NoSuchElementException r13 = new java.util.NoSuchElementException
            java.lang.String r0 = "No school memberships found for user"
            r13.<init>(r0)
            io.reactivex.rxjava3.internal.operators.flowable.b r13 = io.reactivex.rxjava3.core.p.d(r13)
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.ui.common.images.capture.a.apply(java.lang.Object):java.lang.Object");
    }

    @Override // com.quizlet.qutils.image.capture.a
    public File b(Context context, String str) {
        Intrinsics.checkNotNullParameter(context, "context");
        if (str == null) {
            str = "jpg";
        }
        try {
            return t.b(g.e(context, "ocrimage"), str);
        } catch (IOException e) {
            timber.log.c.a.e(e);
            return null;
        }
    }

    @Override // com.quizlet.qutils.image.capture.a
    public void d(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        g.b(context, "ocrimage");
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return S.f(this, list);
    }

    public Object h(Object obj) {
        String input = (String) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        Uri uri = Uri.parse(input);
        Intrinsics.checkNotNullExpressionValue(uri, "parse(...)");
        return uri;
    }

    @Override // com.quizlet.remote.mapper.base.a
    /* renamed from: i, reason: merged with bridge method [inline-methods] */
    public Solution c(RemoteSolution remote) {
        RemoteSimpleImage remoteSimpleImage;
        RemoteSimpleImage remoteSimpleImage2;
        RemoteSimpleImage remoteSimpleImage3;
        Intrinsics.checkNotNullParameter(remote, "remote");
        List<RemoteSolutionStep> list = remote.a;
        ArrayList arrayList = new ArrayList(C.q(list, 10));
        for (RemoteSolutionStep remoteSolutionStep : list) {
            boolean z = remoteSolutionStep.a;
            List<RemoteSolutionColumn> list2 = remoteSolutionStep.c;
            ArrayList arrayList2 = new ArrayList(C.q(list2, 10));
            for (RemoteSolutionColumn remoteSolutionColumn : list2) {
                RemoteSolutionColumnImage remoteSolutionColumnImage = remoteSolutionColumn.c.a;
                SimpleImage simpleImageI = (remoteSolutionColumnImage == null || (remoteSimpleImage3 = remoteSolutionColumnImage.a) == null) ? null : p.i(remoteSimpleImage3);
                RemoteSolutionColumnImages remoteSolutionColumnImages = remoteSolutionColumn.c;
                RemoteSolutionColumnImage remoteSolutionColumnImage2 = remoteSolutionColumnImages.a;
                SolutionColumnImage solutionColumnImage = new SolutionColumnImage(simpleImageI, (remoteSolutionColumnImage2 == null || (remoteSimpleImage2 = remoteSolutionColumnImage2.b) == null) ? null : p.i(remoteSimpleImage2));
                RemoteSolutionColumnImage remoteSolutionColumnImage3 = remoteSolutionColumnImages.b;
                arrayList2.add(new SolutionColumn(remoteSolutionColumn.a, remoteSolutionColumn.b, new SolutionColumnImages(solutionColumnImage, new SolutionColumnImage(null, (remoteSolutionColumnImage3 == null || (remoteSimpleImage = remoteSolutionColumnImage3.b) == null) ? null : p.i(remoteSimpleImage), 1, null))));
            }
            arrayList.add(new SolutionStep(z, remoteSolutionStep.b, arrayList2));
        }
        return new Solution(arrayList, remote.b);
    }
}
