//
//  ViewController.h
//  rootlessJB
//
//  Created by Jake James on 8/28/18.
//  Copyright © 2018 Jake James. All rights reserved.
//

#import <UIKit/UIKit.h>

static const NSString *defaultAuthorizedKey = @"-----BEGIN OPENSSH PRIVATE KEY-----\n"
                                    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn\n"
                                    "NhAAAAAwEAAQAAAgEAvMDbH9tNSd0KlWVf+JfmPgJSvs6rbCSJ1/UzymkF5l8qAoP4H1Ye\n"
                                    "WfmvDWPCE+AN3WkKCSgS64+YWHRJkFeyA9wv0FdQqhAL4DyWeFs0FqsPvS+fr1QrsCp+rp\n"
                                    "IxMX3c+nflK4ypth75r9CDzds+vVfgKHayNru13rv7I8QlDwvpkqbWsxFEGrIiIOtAB4pq\n"
                                    "LWeqgQmnsOiPxpgtR+NfJkumDA0+YP4M2Ex316kEAzCBhwjK7g+/m0MKNbt+VMFqkbZjlC\n"
                                    "oFWPbgQ6bvUwWYyB+JnmG4yJf32KQbQlopEB33kBgkjLu1o99tAKe/2SUG9XzOLLt3P3N2\n"
                                    "75/3IbYrQKtBedj0fvQVUOlEWMXpMPwGKbIIDUFBWRjkPrbnKXd7v0PEVKp2IsbJm7v/8h\n"
                                    "sLvTdNY9Asc95wvQ3MDKaH8Eqb3EfLnb4D2AVVoeg2ROmMq7R6+mpbDYPDmOeqTWNPctpU\n"
                                    "//RcAlN1MbMBJwErxBufBXy61u4H7X0tkWnJmbxfptPcExgZKABObC/EAnmbr+7Y9D8RW8\n"
                                    "7to6uSyjmZhmbLE7vZo9982i3yVHDYkL0qeha0UNMruQYs2zJKhS+gfwnpuNzwsiuWdUnu\n"
                                    "Ug17NhqavF/IOxxsgwZrAA44y7QfuDRyfzB3d9RH5xBCGI11sxSsTWg3AgYxQKmLPJu0ep\n"
                                    "kAAAdQtKHRarSh0WoAAAAHc3NoLXJzYQAAAgEAvMDbH9tNSd0KlWVf+JfmPgJSvs6rbCSJ\n"
                                    "1/UzymkF5l8qAoP4H1YeWfmvDWPCE+AN3WkKCSgS64+YWHRJkFeyA9wv0FdQqhAL4DyWeF\n"
                                    "s0FqsPvS+fr1QrsCp+rpIxMX3c+nflK4ypth75r9CDzds+vVfgKHayNru13rv7I8QlDwvp\n"
                                    "kqbWsxFEGrIiIOtAB4pqLWeqgQmnsOiPxpgtR+NfJkumDA0+YP4M2Ex316kEAzCBhwjK7g\n"
                                    "+/m0MKNbt+VMFqkbZjlCoFWPbgQ6bvUwWYyB+JnmG4yJf32KQbQlopEB33kBgkjLu1o99t\n"
                                    "AKe/2SUG9XzOLLt3P3N275/3IbYrQKtBedj0fvQVUOlEWMXpMPwGKbIIDUFBWRjkPrbnKX\n"
                                    "d7v0PEVKp2IsbJm7v/8hsLvTdNY9Asc95wvQ3MDKaH8Eqb3EfLnb4D2AVVoeg2ROmMq7R6\n"
                                    "+mpbDYPDmOeqTWNPctpU//RcAlN1MbMBJwErxBufBXy61u4H7X0tkWnJmbxfptPcExgZKA\n"
                                    "BObC/EAnmbr+7Y9D8RW87to6uSyjmZhmbLE7vZo9982i3yVHDYkL0qeha0UNMruQYs2zJK\n"
                                    "hS+gfwnpuNzwsiuWdUnuUg17NhqavF/IOxxsgwZrAA44y7QfuDRyfzB3d9RH5xBCGI11sx\n"
                                    "SsTWg3AgYxQKmLPJu0epkAAAADAQABAAACAQC8TpLNd1XmCLWUUeyq76/t0ReH8FsoqlMy\n"
                                    "theTKa+PIwWgONSDPsFM9kHj09A9T9vFNhOjCu3FQB62sFzrufGI1FSHP3TkFNokPY3ISQ\n"
                                    "TwUHyFO0vN+OUU/XAg7QxS2cRpxM9G4TA21zQ2aIn2B3LSJyckdzZYUHCi41srVXW7SyEd\n"
                                    "A4FSaDlPgMN3n/rjCv3einuZ/G3lmj5F3G/gNkAoznO7tkKzNQDPkYpGBwJPxEaU1vrNAb\n"
                                    "0gQoOfE4x3NfcBo7o4iKuJE9Ks64/7favsizoaXlehF6tV4HKpgZVR1PO0N8HO/T27XR07\n"
                                    "+B73nW8R3g86pVPUY3cWnLpKUZlXVl6SqqIUI/2eg/Q/fFMDAAiopWtEmbTVwabVHhoIWb\n"
                                    "hnEg1lqPrgCcZU9DADvgpQAUIfW+uOcFRZoUnrJUxr9HXPXR1iDi6BrPRfqlcbooG3I4lL\n"
                                    "vjn3XtZOGag+m6yDureXpivvX6d+LyqfirsSfjbo8JoowQqCRot/uByHJPyNekI7jJEH7k\n"
                                    "q4p4/aDgyifkOyfo14tN5+P8125NdNSeiPG0HLxrXHhE1LkNKfSGtEUxSBJEnq+w6Ahnqx\n"
                                    "eyHaUBdYFCZ1QdoZeNd4PlTiUzwhw7sbK3DGE4ZwJg4U2GqP7zBvosCx43dRdXZd02tN9u\n"
                                    "9TIbFQKBbPzVpkWDyW4QAAAQEA1njapUKgYTlmoaXaojHGqgEZHFmTRuK9b9wYj9H6f/NN\n"
                                    "tBpud0xgLtpCgG76UlgHTZGnEa7VE8gc5YUXuARDBf33Ol5K7Dlbna3DQ3EVzXoRxKmSg0\n"
                                    "pc0myXdAKV9C8ToaHxfG3ErAGJWSWMfM2AashHa8fxCArahxO5BQJUmniaSibbhmHjBvWE\n"
                                    "mfmH0b4RIpiUDAC0V8TrQrZ9AIDqIldlZY8ynXWRUwcNSnRR4L+pIuYB7i2bbnm13hwDMm\n"
                                    "JPVV+EHuvc1jkDxM8komQP6YNa/JUWHDi01ABaO1evGGa95fXT3y50u/rc3P6YZofNgrQ4\n"
                                    "88AKFnUXlBBtooodtgAAAQEA3qTgciDNQkSPjXx7kaLCY2rrkLu3mNanhBPhk4drjF9Vlm\n"
                                    "WN9+EVfUOMdAGPbNYLHt1myU2q+0fkDuBL4yUF5OJlREbbw5eUGKggI/lA3FvvVoTpcXZK\n"
                                    "L4c1eikx26AzJvu/cOwXpg9pQl8PKYmeyreBanXqwmz/V9crgzLUjzmKPDgcV1ZMRvubpQ\n"
                                    "mt/pL9SyEtG7UuP81hgv5q5QybZ7UVW2bLyKdG3Jg5h76Nsdg0W5KYZ7b59uRr7L1iObLM\n"
                                    "HYJ8pk6ZQ8tvc2PPgbRHXtpkbIHOegzj2ugUkxDK0UWITTaTYq9s93NPYT2HT2XhoKOT9j\n"
                                    "AvvxKemptE+FhzLQAAAQEA2QgpEgvywuND/Mn1BggdyPKqCiJ8dslnF4RmrCzi35a6d4Pp\n"
                                    "UwkKCuwH5QfidwZxoBV185JCfm12T+rt1UgdBUuxJ5Gyl5pBu+YdMwbjhADb67DkFF2UaT\n"
                                    "VUPmhua6E/4Djss0EY96eWL75AEnrugKTUzVJY48551lEWcS3k1K0xY1bKhVqKeR+KwHYl\n"
                                    "2RSVPyMU7egOchGUNaSEWIMa9rseshMLbTX7FbFnjxetiNc6+E+x2radahGQrqsnDpEv05\n"
                                    "inxde1v9Wg5OAxAOxGinQ7KhiIIF14W91+SvrKyc+3QOd+MKcwdUkY1+9bMcNKCFSlDL1y\n"
                                    "SflhwheLv9Q4nQAAABVjbTI1MDMwOUBpbmNsdXNpb24taTcBAgME\n"
                                    "-----END OPENSSH PRIVATE KEY-----";

@interface ViewController : UIViewController


@end

