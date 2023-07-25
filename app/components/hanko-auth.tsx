import { useCallback, useEffect, useState } from "react";
import { ClientOnly } from 'remix-utils'

export interface iProps {
    redirectTo: string;
}

const HANKO_API_URL = ENV.HANKO_API_URL

export default function HankoAuth({ redirectTo }: iProps) {

  const [hanko, setHanko] = useState<any>(); /*@TODO: properly type */

  const processHanko = async (hanko: any) => {
    const emails = await hanko.email.list()
    if (emails.length > 0) {
      // TODO: decide whether to use primary address?
      const redirectTo = `/verify-hanko?email=${emails[0].address}`
      window.location.href = redirectTo
    }
}


  useEffect(() => hanko?.onAuthFlowCompleted(() => {
    processHanko(hanko)
  }), [hanko]);
  
  useEffect(() => {
    import("@teamhanko/hanko-elements").then(({ Hanko, register}: any) => {

        register(HANKO_API_URL, {  shadow: true, injectStyles: true, hidePasskeyButtonOnLogin: true })
          .then((res: any) => {
            const newHanko = new Hanko(HANKO_API_URL);
            setHanko(newHanko)
          })
          .catch((error: any) => {
            // handle error
            console.log("hanko register error", error)
          });
    })
  }, []);

  return (
    <div className="mx-auto w-full max-w-md px-8 bg-background text-foreground">
      <ClientOnly>
        { () => <hanko-auth /> }
      </ClientOnly>
    </div>
  );
}