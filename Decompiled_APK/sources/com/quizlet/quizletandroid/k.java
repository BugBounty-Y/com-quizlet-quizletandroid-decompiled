package com.quizlet.quizletandroid;

import android.content.Context;
import android.content.Intent;
import android.content.res.TypedArray;
import android.net.Uri;
import android.util.AttributeSet;
import com.facebook.AccessToken;
import com.facebook.FacebookException;
import com.google.android.gms.internal.ads.Zh;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3241q5;
import com.google.android.gms.internal.mlkit_vision_barcode.S;
import com.google.android.gms.internal.mlkit_vision_barcode.T;
import com.quizlet.data.model.EnumC4175w;
import com.quizlet.data.model.H0;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.data.model.NotesToValueInfo;
import com.quizlet.data.model.TableOfContentItem;
import com.quizlet.data.model.TableOfContents;
import com.quizlet.data.model.Textbook;
import com.quizlet.data.model.TitleInfo;
import com.quizlet.db.data.models.persisted.DBGroupMembership;
import com.quizlet.db.data.models.persisted.DBImage;
import com.quizlet.db.data.models.persisted.DBStudySet;
import com.quizlet.db.data.models.persisted.DBTerm;
import com.quizlet.db.data.models.persisted.base.Models;
import com.quizlet.quizletandroid.ui.group.GroupFragment;
import com.quizlet.quizletandroid.ui.login.FacebookAuthActivity;
import com.quizlet.quizletandroid.ui.setcreation.fragments.ScanDocumentFragment;
import com.quizlet.quizletandroid.ui.shortcuts.CreateSetShortcutInterstitialActivity;
import com.quizlet.quizletandroid.ui.startpage.nav2.Y;
import com.quizlet.quizletandroid.ui.startpage.nav2.model.P;
import com.quizlet.remote.model.base.ApiThreeWrapper;
import com.quizlet.remote.model.explanations.textbook.RemoteTextbook;
import com.quizlet.remote.model.notes.MagicNotesArtifactResponse;
import com.quizlet.remote.model.notes.MagicNotesTitleArtifactResponse;
import com.quizlet.remote.model.user.FullUserModels;
import com.quizlet.remote.model.user.FullUserResponse;
import com.quizlet.remote.model.user.RemoteFullUser;
import com.quizlet.scandocument.ui.OcrToolbarView;
import com.quizlet.shared.enums.studynotes.StudyNotesArtifactType$Companion;
import com.quizlet.uicommon.ui.common.dialogs.ImageOverlayDialogFragment;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import kotlin.collections.CollectionsKt;
import kotlin.collections.K;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import retrofit2.C5183h;
import retrofit2.InterfaceC5181f;

/* loaded from: classes3.dex */
public final class k implements dagger.android.b, io.reactivex.rxjava3.functions.h, com.facebook.l, com.quizlet.qutils.image.capture.b, io.reactivex.rxjava3.functions.e, com.quizlet.remote.mapper.base.b, com.quizlet.mapper.a, InterfaceC5181f {
    public final /* synthetic */ int a;
    public Object b;

    public /* synthetic */ k(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void r() {
    }

    @Override // com.quizlet.mapper.a
    public Object a(Object obj) {
        MagicNotesArtifactResponse input = (MagicNotesArtifactResponse) obj;
        Intrinsics.checkNotNullParameter(input, "input");
        String str = input.e;
        StudyNotesArtifactType$Companion studyNotesArtifactType$Companion = com.quizlet.shared.enums.studynotes.f.Companion;
        if (!Intrinsics.b(str, "title")) {
            return null;
        }
        EnumC4175w enumC4175w = (EnumC4175w) ((kotlin.enums.b) EnumC4175w.a()).get(input.f);
        com.squareup.moshi.D d = (com.squareup.moshi.D) this.b;
        d.getClass();
        MagicNotesTitleArtifactResponse magicNotesTitleArtifactResponse = (MagicNotesTitleArtifactResponse) d.a(MagicNotesTitleArtifactResponse.class, com.squareup.moshi.internal.b.a, null).b(input.d);
        return new TitleInfo(input.a, enumC4175w, magicNotesTitleArtifactResponse != null ? magicNotesTitleArtifactResponse.a : null);
    }

    @Override // io.reactivex.rxjava3.functions.h
    public Object apply(Object obj) {
        FullUserModels fullUserModels;
        List list;
        boolean z = true;
        int i = 0;
        switch (this.a) {
            case 1:
                DBTerm dBTerm = (DBTerm) obj;
                Intrinsics.d(dBTerm);
                com.google.android.datatransport.cct.internal.s sVar = (com.google.android.datatransport.cct.internal.s) this.b;
                DBImage definitionImage = dBTerm.getDefinitionImage();
                String serverSquareUrl = definitionImage != null ? definitionImage.getServerSquareUrl() : null;
                com.quizlet.quizletandroid.ui.common.images.loading.offline.c cVar = (com.quizlet.quizletandroid.ui.common.images.loading.offline.c) sVar.c;
                io.reactivex.rxjava3.core.a aVarI = com.google.android.datatransport.cct.internal.s.i(serverSquareUrl, cVar);
                DBImage definitionImage2 = dBTerm.getDefinitionImage();
                io.reactivex.rxjava3.core.a aVarI2 = com.google.android.datatransport.cct.internal.s.i(definitionImage2 != null ? definitionImage2.getServerSmallUrl() : null, cVar);
                DBImage definitionImage3 = dBTerm.getDefinitionImage();
                io.reactivex.rxjava3.core.a aVarI3 = com.google.android.datatransport.cct.internal.s.i(definitionImage3 != null ? definitionImage3.getServerMediumUrl() : null, cVar);
                DBImage definitionImage4 = dBTerm.getDefinitionImage();
                io.reactivex.rxjava3.core.a aVarI4 = com.google.android.datatransport.cct.internal.s.i(definitionImage4 != null ? definitionImage4.getServerLargeUrl() : null, cVar);
                String definitionAudioUrl = dBTerm.getDefinitionAudioUrl();
                com.quizlet.quizletandroid.managers.audio.g gVar = (com.quizlet.quizletandroid.managers.audio.g) sVar.b;
                io.reactivex.rxjava3.core.a aVarD = io.reactivex.rxjava3.core.a.d(aVarI, aVarI2, aVarI3, aVarI4, com.google.android.datatransport.cct.internal.s.i(definitionAudioUrl, gVar), com.google.android.datatransport.cct.internal.s.i(dBTerm.getWordAudioUrl(), gVar));
                Intrinsics.checkNotNullExpressionValue(aVarD, "mergeArray(...)");
                return aVarD;
            case 2:
                Intrinsics.checkNotNullParameter((List) obj, "<unused var>");
                return (com.quizlet.quizletandroid.data.management.a) this.b;
            case 5:
                HashSet userMemberships = (HashSet) obj;
                Intrinsics.checkNotNullParameter(userMemberships, "userMemberships");
                ArrayList arrayList = new ArrayList();
                for (Object obj2 : userMemberships) {
                    if (((DBGroupMembership) obj2).getLevel() >= 0) {
                        arrayList.add(obj2);
                    }
                }
                if (arrayList.isEmpty()) {
                    z = false;
                } else {
                    Iterator it2 = arrayList.iterator();
                    while (it2.hasNext()) {
                        DBGroupMembership dBGroupMembership = (DBGroupMembership) it2.next();
                        if (dBGroupMembership.getLevel() >= 0) {
                            long classId = dBGroupMembership.getClassId();
                            String str = GroupFragment.M;
                            if (classId == ((GroupFragment) this.b).U()) {
                            }
                        }
                    }
                    z = false;
                }
                return new com.quizlet.quizletandroid.ui.group.e(z);
            case 8:
                Intrinsics.checkNotNullParameter((DBStudySet) obj, "it");
                ((Zh) this.b).getClass();
                com.jakewharton.rxbinding4.a aVarO = io.reactivex.rxjava3.core.i.o(kotlin.collections.B.j(Models.IMAGE, Models.TERM, Models.STUDY_SET));
                Intrinsics.checkNotNullExpressionValue(aVarO, "fromIterable(...)");
                return aVarO;
            case 10:
                List it3 = (List) obj;
                Intrinsics.checkNotNullParameter(it3, "it");
                ((Y) this.b).getClass();
                return it3.isEmpty() ? new ArrayList() : O.b(CollectionsKt.y0(Y.F(Y.G(it3), P.e, null)));
            case 12:
                Boolean it4 = (Boolean) obj;
                Intrinsics.checkNotNullParameter(it4, "it");
                if (!it4.booleanValue()) {
                    return (io.reactivex.rxjava3.core.p) this.b;
                }
                io.reactivex.rxjava3.internal.operators.flowable.b bVarF = io.reactivex.rxjava3.core.p.f(Boolean.TRUE);
                Intrinsics.checkNotNullExpressionValue(bVarF, "just(...)");
                return bVarF;
            case 16:
                ApiThreeWrapper response = (ApiThreeWrapper) obj;
                Intrinsics.checkNotNullParameter(response, "response");
                FullUserResponse fullUserResponse = (FullUserResponse) response.a();
                if (fullUserResponse == null || (fullUserModels = fullUserResponse.d) == null || (list = fullUserModels.a) == null) {
                    return K.a;
                }
                ArrayList remotes = new ArrayList(kotlin.collections.C.q(list, 10));
                for (Object obj3 : list) {
                    int i2 = i + 1;
                    if (i < 0) {
                        kotlin.collections.B.p();
                        throw null;
                    }
                    remotes.add((RemoteFullUser) obj3);
                    i = i2;
                }
                com.quizlet.quizletandroid.managers.upgrade.a aVar = (com.quizlet.quizletandroid.managers.upgrade.a) ((com.quizlet.remote.model.user.a) this.b).b;
                Intrinsics.checkNotNullParameter(remotes, "remotes");
                return S.f(aVar, remotes);
            default:
                Object[] objArr = (Object[]) obj;
                if (objArr.length == 3) {
                    return ((io.reactivex.rxjava3.functions.e) this.b).k(objArr[0], objArr[1], objArr[2]);
                }
                throw new IllegalArgumentException("Array of size 3 expected but got " + objArr.length);
        }
    }

    @Override // retrofit2.InterfaceC5181f
    public Type b() {
        return (Type) this.b;
    }

    @Override // dagger.android.b
    public void d(Object obj) {
        ImageOverlayDialogFragment imageOverlayDialogFragment = (ImageOverlayDialogFragment) obj;
        u uVar = (u) this.b;
        imageOverlayDialogFragment.q = uVar.w();
        imageOverlayDialogFragment.w = (com.quizlet.qutils.image.loading.a) uVar.s.get();
    }

    @Override // com.quizlet.remote.mapper.base.a
    public List e(List list) {
        return T.f(this, list);
    }

    @Override // com.facebook.l
    public void f(FacebookException facebookException) {
        timber.log.c.a.q(facebookException, "Error during Facebook authentication", new Object[0]);
        ((FacebookAuthActivity) this.b).finish();
    }

    @Override // com.quizlet.qutils.image.capture.b
    public void g(Uri path) {
        Intrinsics.checkNotNullParameter(path, "path");
        ScanDocumentFragment scanDocumentFragment = (ScanDocumentFragment) this.b;
        scanDocumentFragment.e0().E(path);
        scanDocumentFragment.d0().getOcrImageView().a();
        OcrToolbarView ocrToolbarViewC0 = scanDocumentFragment.c0();
        ocrToolbarViewC0.getClass();
        com.quizlet.scandocument.model.b bVar = com.quizlet.scandocument.model.b.a;
        ocrToolbarViewC0.q = bVar;
        ocrToolbarViewC0.v.b(bVar);
    }

    @Override // com.quizlet.remote.mapper.base.c
    public Object h(Object obj) {
        Textbook data = (Textbook) obj;
        Intrinsics.checkNotNullParameter(data, "data");
        long j = data.a;
        Boolean boolValueOf = Boolean.valueOf(data.f);
        Boolean boolValueOf2 = Boolean.valueOf(data.j);
        List list = data.l;
        ArrayList arrayList = new ArrayList(kotlin.collections.C.q(list, 10));
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            arrayList.add(((com.quizlet.data.repository.folderset.c) this.b).h((TableOfContentItem) it2.next()));
        }
        return new RemoteTextbook(j, data.b, data.c, data.h, data.d, data.i, data.e, boolValueOf, boolValueOf2, data.k, null, data.g, arrayList, false, 9216, null);
    }

    @Override // com.facebook.l
    public void i(com.facebook.login.C c) {
        AccessToken accessToken = c.a;
        Intent intent = new Intent();
        intent.putExtra("com.quizlet.quizletandroid.EXTRA_ACCESS_TOKEN", accessToken.e);
        FacebookAuthActivity facebookAuthActivity = (FacebookAuthActivity) this.b;
        facebookAuthActivity.setResult(-1, intent);
        facebookAuthActivity.finish();
    }

    @Override // retrofit2.InterfaceC5181f
    public Object j(retrofit2.u uVar) {
        C5183h c5183h = new C5183h(uVar);
        uVar.j(new com.quizlet.quizletandroid.ui.login.h(c5183h, 14));
        return c5183h;
    }

    @Override // io.reactivex.rxjava3.functions.e
    public Object k(Object obj, Object obj2, Object obj3) {
        Boolean smartGradingEnabled = (Boolean) obj;
        Boolean isPlusUser = (Boolean) obj2;
        Boolean isPaidTeacher = (Boolean) obj3;
        Intrinsics.checkNotNullParameter(smartGradingEnabled, "smartGradingEnabled");
        Intrinsics.checkNotNullParameter(isPlusUser, "isPlusUser");
        Intrinsics.checkNotNullParameter(isPaidTeacher, "isPaidTeacher");
        return Boolean.valueOf(smartGradingEnabled.booleanValue() && (isPlusUser.booleanValue() || isPaidTeacher.booleanValue() || AbstractC3241q5.d(AbstractC3241q5.e((InterfaceC4176w0) this.b))));
    }

    /* JADX WARN: Removed duplicated region for block: B:8:0x0014  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object l(long r10, long r12, com.quizlet.remote.model.base.PagingInfo r14, kotlin.coroutines.jvm.internal.c r15) {
        /*
            r9 = this;
            boolean r0 = r15 instanceof com.quizlet.remote.model.selectedterm.d
            if (r0 == 0) goto L14
            r0 = r15
            com.quizlet.remote.model.selectedterm.d r0 = (com.quizlet.remote.model.selectedterm.d) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L14
            int r1 = r1 - r2
            r0.m = r1
        L12:
            r7 = r0
            goto L1a
        L14:
            com.quizlet.remote.model.selectedterm.d r0 = new com.quizlet.remote.model.selectedterm.d
            r0.<init>(r9, r15)
            goto L12
        L1a:
            java.lang.Object r15 = r7.k
            kotlin.coroutines.intrinsics.a r0 = kotlin.coroutines.intrinsics.a.a
            int r1 = r7.m
            r2 = 1
            if (r1 == 0) goto L36
            if (r1 != r2) goto L2e
            com.quizlet.remote.model.base.a r10 = r7.j
            androidx.glance.appwidget.protobuf.Z.e(r15)     // Catch: java.lang.Exception -> L2b
            goto L5c
        L2b:
            r0 = move-exception
            r10 = r0
            goto L63
        L2e:
            java.lang.IllegalStateException r10 = new java.lang.IllegalStateException
            java.lang.String r11 = "call to 'resume' before 'invoke' with coroutine"
            r10.<init>(r11)
            throw r10
        L36:
            androidx.glance.appwidget.protobuf.Z.e(r15)
            com.quizlet.remote.model.base.a r15 = com.quizlet.remote.model.base.a.a
            java.lang.Object r1 = r9.b     // Catch: java.lang.Exception -> L2b
            com.quizlet.remote.service.z r1 = (com.quizlet.remote.service.z) r1     // Catch: java.lang.Exception -> L2b
            if (r14 == 0) goto L47
            java.util.LinkedHashMap r14 = r14.a()     // Catch: java.lang.Exception -> L2b
        L45:
            r6 = r14
            goto L4c
        L47:
            kotlin.collections.L r14 = kotlin.collections.V.c()     // Catch: java.lang.Exception -> L2b
            goto L45
        L4c:
            r7.j = r15     // Catch: java.lang.Exception -> L2b
            r7.m = r2     // Catch: java.lang.Exception -> L2b
            r2 = r10
            r4 = r12
            java.lang.Object r10 = r1.b(r2, r4, r6, r7)     // Catch: java.lang.Exception -> L2b
            if (r10 != r0) goto L59
            return r0
        L59:
            r8 = r15
            r15 = r10
            r10 = r8
        L5c:
            com.quizlet.remote.model.base.ApiThreeWrapper r15 = (com.quizlet.remote.model.base.ApiThreeWrapper) r15     // Catch: java.lang.Exception -> L2b
            java.lang.Object r10 = com.google.android.gms.internal.mlkit_vision_barcode.V.c(r15, r10)     // Catch: java.lang.Exception -> L2b
            return r10
        L63:
            kotlin.p r11 = kotlin.r.b
            kotlin.q r10 = androidx.glance.appwidget.protobuf.Z.b(r10)
            return r10
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.quizletandroid.k.l(long, long, com.quizlet.remote.model.base.PagingInfo, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public com.snowplowanalytics.core.statemachine.d m(String stateIdentifier) {
        Intrinsics.checkNotNullParameter(stateIdentifier, "stateIdentifier");
        com.snowplowanalytics.core.statemachine.e eVarN = n(stateIdentifier);
        if (eVarN == null) {
            return null;
        }
        return eVarN.a();
    }

    public synchronized com.snowplowanalytics.core.statemachine.e n(String stateIdentifier) {
        Intrinsics.checkNotNullParameter(stateIdentifier, "stateIdentifier");
        return (com.snowplowanalytics.core.statemachine.e) ((HashMap) this.b).get(stateIdentifier);
    }

    public void o(Context context, AttributeSet attributeSet) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attributeSet, "attributeSet");
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, I.f, 0, 0);
        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        s(typedArrayObtainStyledAttributes.getResourceId(0, ((com.quizlet.quizletandroid.ui.activitycenter.views.h) this.b).a.a));
        typedArrayObtainStyledAttributes.recycle();
    }

    @Override // com.facebook.l
    public void onCancel() {
        switch (this.a) {
            case 6:
                ((FacebookAuthActivity) this.b).finish();
                break;
        }
    }

    public ArrayList p(List studyNotes) {
        Intrinsics.checkNotNullParameter(studyNotes, "studyNotes");
        LinkedHashMap linkedHashMap = new LinkedHashMap();
        long jCurrentTimeMillis = System.currentTimeMillis();
        Iterator it2 = studyNotes.iterator();
        while (it2.hasNext()) {
            NotesToValueInfo notesToValueInfo = (NotesToValueInfo) it2.next();
            long j = notesToValueInfo.l;
            com.quizlet.quizletandroid.util.o oVar = (com.quizlet.quizletandroid.util.o) this.b;
            String strB = oVar.b(jCurrentTimeMillis, oVar.a(jCurrentTimeMillis, j));
            if (!linkedHashMap.containsKey(strB)) {
                linkedHashMap.put(strB, new ArrayList());
            }
            List list = (List) linkedHashMap.get(strB);
            if (list != null) {
                list.add(notesToValueInfo);
            }
        }
        ArrayList arrayList = new ArrayList(linkedHashMap.size());
        for (Map.Entry entry : linkedHashMap.entrySet()) {
            arrayList.add(new H0((String) entry.getKey(), (List) entry.getValue()));
        }
        return arrayList;
    }

    @Override // com.quizlet.remote.mapper.base.a
    /* renamed from: q, reason: merged with bridge method [inline-methods] */
    public Textbook c(RemoteTextbook remote) {
        Intrinsics.checkNotNullParameter(remote, "remote");
        long j = remote.a;
        String str = remote.c;
        String str2 = str == null ? "" : str;
        String str3 = remote.d;
        String str4 = str3 == null ? "" : str3;
        String str5 = remote.e;
        String str6 = str5 == null ? "" : str5;
        String str7 = remote.f;
        String str8 = str7 == null ? "" : str7;
        String str9 = remote.g;
        String str10 = str9 == null ? "" : str9;
        Boolean bool = remote.h;
        boolean zBooleanValue = bool != null ? bool.booleanValue() : false;
        Boolean bool2 = remote.i;
        boolean zBooleanValue2 = bool2 != null ? bool2.booleanValue() : false;
        String str11 = remote.j;
        String str12 = str11 == null ? "" : str11;
        Iterable iterable = remote.m;
        if (iterable == null) {
            iterable = K.a;
        }
        ArrayList items = new ArrayList(kotlin.collections.C.q(iterable, 10));
        Iterator it2 = iterable.iterator();
        while (it2.hasNext()) {
            items.add(((com.quizlet.data.repository.folderset.c) this.b).c((com.quizlet.remote.model.explanations.toc.a) it2.next()));
        }
        K k = TableOfContents.b;
        Intrinsics.checkNotNullParameter(items, "items");
        return new Textbook(j, remote.b, str2, str6, str10, zBooleanValue, remote.l, str4, str8, zBooleanValue2, str12, items);
    }

    public void s(int i) {
        com.quizlet.quizletandroid.ui.activitycenter.views.f fVar = ((com.quizlet.quizletandroid.ui.activitycenter.views.h) this.b).b;
        fVar.getCount().setBackgroundResource(i);
        fVar.h().setBackgroundResource(i);
    }

    public k(CreateSetShortcutInterstitialActivity view, com.quizlet.infra.legacysyncengine.managers.d loggedInUserManager) {
        this.a = 9;
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(loggedInUserManager, "loggedInUserManager");
        this.b = view;
    }

    public k(com.quizlet.data.repository.folderset.c tocMapper) {
        this.a = 13;
        Intrinsics.checkNotNullParameter(tocMapper, "tocMapper");
        this.b = tocMapper;
    }

    public k(com.quizlet.quizletandroid.util.o timestampFormatter) {
        this.a = 3;
        Intrinsics.checkNotNullParameter(timestampFormatter, "timestampFormatter");
        this.b = timestampFormatter;
    }

    public k(com.quizlet.remote.service.z service) {
        this.a = 15;
        Intrinsics.checkNotNullParameter(service, "service");
        this.b = service;
    }

    public k(int i) {
        this.a = i;
        switch (i) {
            case 17:
                this.b = new HashMap();
                break;
            default:
                com.squareup.moshi.D d = new com.squareup.moshi.D(new com.google.firebase.crashlytics.internal.metadata.p(1));
                Intrinsics.checkNotNullExpressionValue(d, "build(...)");
                this.b = d;
                break;
        }
    }

    public k(kotlinx.serialization.json.c json) {
        this.a = 21;
        Intrinsics.checkNotNullParameter(json, "json");
        this.b = json;
    }

    public k(Context context, com.quizlet.quizletandroid.ui.activitycenter.views.h config) {
        this.a = 4;
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(config, "config");
        this.b = config;
    }

    public k(kotlin.text.m match) {
        this.a = 19;
        Intrinsics.checkNotNullParameter(match, "match");
        this.b = match;
    }
}
