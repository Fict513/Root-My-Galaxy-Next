package dev.busung.s25uroot

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The hardware-tested Galaxy S23 `SM-S911B` / `S911BXXSAFZG1` profile added to the default feed.
 *
 * The device-specific risk this profile carries is not "does a kernel match" in general - that is
 * already covered by [TargetProfileTest] - but that this *particular* entry must never answer for a
 * kernel it was not validated on. `SM-S911B` shipped at least three different `5.15.189` builds
 * (`SAFZE1`, `U9FZDP`, `SAFZG1`), each with its own data offsets, and only `SAFZG1` is the one this
 * profile's `cve-2026-43499-app.so` and `ksud` were built and hardware-verified against. So every
 * test here is a way that a looser match would have quietly handed one of those builds, or another
 * `dm1q`/`dm3q` model entirely, a payload it was never tested with.
 */
class Sm911bSafzg1Test {

    private val fzg1KernelRelease = "5.15.189-android13-8-33413713-abS911BXXSAFZG1"

    /** The exact entry added to `support/targets-v3.json` in the Payloads feed. */
    private val fzg1 = TargetProfile(
        profileId = "dm1q-S911BXXSAFZG1",
        displayName = "Galaxy S23 SM-S911B | Kernel 5.15.189 (S911BXXSAFZG1)",
        models = setOf("SM-S911B"),
        kernelVersions = setOf(fzg1KernelRelease),
        exploit = RemoteArtifact(
            url = "https://raw.githubusercontent.com/rushiranpise/Root-My-Galaxy-Payloads/main/" +
                "artifacts/dm1q-S911BXXSAFZG1/cve-2026-43499-app.so",
            size = 130608,
            sha256 = "7b1ad03f8136e5d130e3f77c0a71a7be87ac301b07b3829e9956c5199d538b06",
        ),
        kernelSu = RemoteArtifact(
            url = "https://raw.githubusercontent.com/rushiranpise/Root-My-Galaxy-Payloads/main/" +
                "kernelsu/ksud-dm1q-S911BXXSAFZG1-kdp",
            size = 4879560,
            sha256 = "07302e5a79cc6c57d23a06cbb996c2f31c50c29589c03cf40278cfe43ab92639",
        ),
    )

    /** `dm2q`/`SM-S916B` carries its own FZG1-labelled build on the same kernel family and must stay separate. */
    private val s916b = fzg1.copy(
        profileId = "dm2q-S916BXXSAFZG1",
        models = setOf("SM-S916B"),
        kernelVersions = setOf("5.15.189-android13-8-33413713-abS916BXXSAFZG1"),
    )

    /** `dm3q`/`SM-S918B` is the existing, already-shipped S23 Ultra entry on the same kernel family. */
    private val s918b = fzg1.copy(
        profileId = "dm3q-S918BXXSAFZF5",
        models = setOf("SM-S918B"),
        kernelVersions = setOf("5.15.189"),
    )

    private val catalog = listOf(fzg1, s916b, s918b)

    private fun snapshot(model: String, device: String, kernelRelease: String) = DeviceSnapshot(
        manufacturer = "samsung",
        model = model,
        device = device,
        kernelRelease = kernelRelease,
        kernelVersionInfo = "#1 SMP PREEMPT",
        machine = "aarch64",
        buildId = "BP4A.251205.006",
        fingerprint = "samsung/$device/$device:16/BP4A.251205.006/$model" +
            "XXSAFZG1:user/release-keys",
        androidRelease = "16",
        sdk = 36,
        abi = "arm64-v8a",
        pageSize = 4096,
    )

    // 1. SM-S911B + exact FZG1 kernel => target matches.
    @Test
    fun theRealDeviceOnItsExactTestedKernelMatches() {
        val device = snapshot("SM-S911B", "dm1q", fzg1KernelRelease)
        assertTrue(fzg1.matches(device))
        assertEquals(KernelMatch.Exact, fzg1.kernelMatch(device))
    }

    // 2. SM-S911B + different kernel string => does NOT match.
    @Test
    fun theSameModelOnAnyOtherS911BKernelBuildDoesNotMatch() {
        val fze1 = snapshot("SM-S911B", "dm1q", "5.15.189-android13-8-33413713-abS911BXXSAFZE1")
        val fzdp = snapshot("SM-S911B", "dm1q", "5.15.189-android13-8-33413713-abS911BXXU9FZDP")

        assertFalse(fzg1.matches(fze1))
        assertFalse(fzg1.matches(fzdp))
        assertEquals(KernelMatch.None, fzg1.kernelMatch(fze1))
        assertEquals(KernelMatch.None, fzg1.kernelMatch(fzdp))
        assertNull(listOf(fzg1).resolveFor(fze1))
        assertNull(listOf(fzg1).resolveFor(fzdp))
    }

    // 3. SM-S916B + FZG1-like kernel => does NOT select the dm1q target.
    @Test
    fun anS916bOnItsOwnFzg1BuildNeverResolvesToTheDm1qProfile() {
        val device = snapshot(
            "SM-S916B",
            "dm2q",
            "5.15.189-android13-8-33413713-abS916BXXSAFZG1",
        )

        assertFalse(fzg1.matches(device))
        val resolved = catalog.resolveFor(device)
        assertEquals("dm2q-S916BXXSAFZG1", resolved?.profileId)
    }

    // 4. SM-S918B => does NOT select the dm1q target.
    @Test
    fun anS918bNeverResolvesToTheDm1qProfile() {
        val device = snapshot("SM-S918B", "dm3q", "5.15.189-android13-8-33413713-abS918BXXSAFZF5")

        assertFalse(fzg1.matches(device))
        val resolved = catalog.resolveFor(device)
        assertEquals("dm3q-S918BXXSAFZF5", resolved?.profileId)
    }

    // 5. Generic android13-5.15 KMI alone is insufficient to select this exploit profile.
    @Test
    fun theSharedKmiAloneIsNotEnoughToSelectTheExploitProfile() {
        // Every one of these three builds reads as the same `android13-5.15` KMI, which is the fact
        // the generic KernelSU daemon tier may use once a target has already been chosen - not the
        // fact that chooses the exploit target itself. If the KMI alone were accepted, any of the
        // three S911B builds (or the S916B/S918B siblings sharing the same family) would have run
        // the exact SAFZG1-tuned offsets on hardware they were never derived from.
        val fze1 = snapshot("SM-S911B", "dm1q", "5.15.189-android13-8-33413713-abS911BXXSAFZE1")
        assertEquals("android13-5.15", fze1.kmi)
        assertEquals("android13-5.15", fzg1KernelRelease.kmi())
        assertFalse(fzg1.matches(fze1))
        assertNull(listOf(fzg1).resolveFor(fze1))
    }

    // 6. Exact target returns the correct payload ID.
    @Test
    fun theResolvedProfileIsTheExactPayloadId() {
        val device = snapshot("SM-S911B", "dm1q", fzg1KernelRelease)
        assertEquals("dm1q-S911BXXSAFZG1", catalog.resolveFor(device)?.profileId)
    }

    // 7. Correct transport policy is selected.
    @Test
    fun noShellOnlyTransportIsForcedForThisProfile() {
        // The feed carries no per-entry route policy (see [ExploitRoutePolicy]); every profile runs
        // under the app's one global policy, and `prefersShellTransport` defaults to false. That is
        // the right answer for this profile specifically: the hardware test root'd through both the
        // app's own Shizuku-mediated run and a plain `adb shell` invocation of the same artifact, so
        // this entry must not be the one that starts silently forcing - or silently downgrading from -
        // a shell transport the app never declared.
        val policy = ExploitRoutePolicy()
        assertFalse(policy.prefersShellTransport)
    }

    // 8. Correct KernelSU flavour/version metadata is parsed.
    @Test
    fun theEntryParsesAsPlainKernelSuWithNoVersionOverride() {
        val parsed = SupportManifest.parse(manifestJson())
        val target = parsed.targets.single { it.profileId == "dm1q-S911BXXSAFZG1" }

        // Preserve the hardware-tested KernelSU late-load path: no "flavor" key in the feed entry
        // means this profile must resolve to plain KernelSU, not KernelSU-Next or ReSukiSU.
        assertEquals(KernelSuFlavor.KernelSu, target.flavor)
        // No "version" key was declared for this device-specific ksud build, so none should be
        // invented here; the flavour's own release stands in for display purposes.
        assertNull(target.kernelSuVersion)
        assertEquals(4879560L, target.kernelSu.size)
        assertEquals(
            "07302e5a79cc6c57d23a06cbb996c2f31c50c29589c03cf40278cfe43ab92639",
            target.kernelSu.sha256,
        )
    }

    // 9. Payload source priority resolves personal fork first without removing upstream fallback.
    @Test
    fun payloadSourceDefaultsPrioritizeThePersonalForkAndKeepBothFallbacks() {
        val defaults = PayloadSource.DEFAULTS
        assertEquals("Fict513/Root-My-Galaxy-Payloads@feature/dm1q-s911b-fzg1", defaults[0].id)
        assertEquals("rushiranpise/Root-My-Galaxy-Payloads@main", defaults[1].id)
        assertEquals("BuSung-dev/Root-My-Galaxy-Payloads@main", defaults[2].id)

        // When two sources both provide the exact target, resolution keeps the source order.
        val device = snapshot("SM-S911B", "dm1q", fzg1KernelRelease)
        val fromPersonal = fzg1.copy(sourceId = defaults[0].id, sourceLabel = defaults[0].label)
        val fromUpstream = fzg1.copy(sourceId = defaults[1].id, sourceLabel = defaults[1].label)
        assertEquals(defaults[0].id, listOf(fromPersonal, fromUpstream).resolveFor(device)?.sourceId)
    }

    // 10. No regression to existing target parsing / existing schema-v3 parsing still works.
    @Test
    fun theNewEntryParsesAlongsideExistingEntriesWithoutDisturbingThem() {
        val parsed = SupportManifest.parse(manifestJson())

        assertEquals(3, parsed.schemaVersion)
        assertEquals(2, parsed.targets.size)

        val dm3q = parsed.targets.single { it.profileId == "dm3q-S918BXXSAFZF5" }
        assertEquals(setOf("SM-S918B"), dm3q.models)
        assertEquals(setOf("5.15.189"), dm3q.kernelVersions)

        val dm1q = parsed.targets.single { it.profileId == "dm1q-S911BXXSAFZG1" }
        assertEquals(setOf("SM-S911B"), dm1q.models)
        assertEquals(setOf(fzg1KernelRelease), dm1q.kernelVersions)
        assertEquals(130608L, dm1q.exploit.size)
        assertEquals(
            "7b1ad03f8136e5d130e3f77c0a71a7be87ac301b07b3829e9956c5199d538b06",
            dm1q.exploit.sha256,
        )

        // Resolving against the real device snapshot still lands on this entry, through the parser
        // and not just through the hand-built [TargetProfile] used in the other tests above.
        val device = snapshot("SM-S911B", "dm1q", fzg1KernelRelease)
        assertEquals("dm1q-S911BXXSAFZG1", parsed.targets.resolveFor(device)?.profileId)
    }

    /** The real feed entry (as added to `support/targets-v3.json`), alongside an unrelated sibling. */
    private fun manifestJson(): ByteArray = """
        {
          "schemaVersion": 3,
          "payloads": [
            {
              "payloadId": "dm3q-S918BXXSAFZF5",
              "displayName": "Galaxy S23 Ultra SM-S918B | Kernel 5.15.189 (S918BXXSAFZF5)",
              "models": ["SM-S918B"],
              "kernelVersions": ["5.15.189"],
              "exploit": {
                "url": "https://raw.githubusercontent.com/rushiranpise/Root-My-Galaxy-Payloads/main/artifacts/dm3q-S918BXXSAFZF5/cve-2026-43499-app.so",
                "size": 135752
              },
              "kernelsu": {
                "url": "https://raw.githubusercontent.com/rushiranpise/Root-My-Galaxy-Payloads/main/kernelsu/ksud-dm3q-S918BXXSAFZF5-kdp",
                "size": 5105552,
                "sha256": "a2cd6c61f73b36867805e3e1e6a412a1d73513e13547da0c44b0f712e23801d4",
                "version": "3.3.0"
              }
            },
            {
              "payloadId": "dm1q-S911BXXSAFZG1",
              "displayName": "Galaxy S23 SM-S911B | Kernel 5.15.189 (S911BXXSAFZG1)",
              "models": ["SM-S911B"],
              "kernelVersions": ["5.15.189-android13-8-33413713-abS911BXXSAFZG1"],
              "exploit": {
                "url": "https://raw.githubusercontent.com/rushiranpise/Root-My-Galaxy-Payloads/main/artifacts/dm1q-S911BXXSAFZG1/cve-2026-43499-app.so",
                "size": 130608,
                "sha256": "7b1ad03f8136e5d130e3f77c0a71a7be87ac301b07b3829e9956c5199d538b06"
              },
              "kernelsu": {
                "url": "https://raw.githubusercontent.com/rushiranpise/Root-My-Galaxy-Payloads/main/kernelsu/ksud-dm1q-S911BXXSAFZG1-kdp",
                "size": 4879560,
                "sha256": "07302e5a79cc6c57d23a06cbb996c2f31c50c29589c03cf40278cfe43ab92639"
              }
            }
          ]
        }
    """.trimIndent().toByteArray()
}
